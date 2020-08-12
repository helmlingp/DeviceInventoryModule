<#
    File: ProfileManagement.psm1
    Author: cbradley@vmware.com
#>

#==========================Header=============================#
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Reg\Polls";
}
$reg_path = $current_path | Split-Path -Parent;
$profile_path = "$reg_path\Profiles";
Unblock-File "$reg_path\Helpers.psm1"
$LocalHelpers = Import-Module "$reg_path\Helpers.psm1" -ErrorAction Stop -PassThru -Force;

$shared_path = $Global:shared_path;

$GlobalModules = @();
$GlobalImporter = @("$reg_path\ProfileManagement.psm1","$reg_path\CustomSettingsLib.psm1",
                         "$shared_path\Database-Management.psm1", "$shared_path\Utility-Functions.psm1");

foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$log_path\PollCounters.log"; 

$CounterDatabase = "$current_path\Counters.db";

$InstallPath = "HKLM:\SOFTWARE\AIRWATCH\InventorySettings\Counters"

Function Set-StoredCounter{
    param($ProfileId, $CounterId, $DateStr, $RegValue, $NoteObject)

    try{
        If($RegValue){
            $UID = "$ProfileId`_$CounterId"
            $InstallPath = "HKLM:\SOFTWARE\AIRWATCH\InventorySettings\Counters"
            $CounterPath = "$InstallPath\$UID"
            If(!(Test-Path $CounterPath)){
                New-Item -Path $CounterPath -Force
            }
        
            $current_sample = Get-ItemPropertyValueSafe -Path $CounterPath -Name $DateStr -DefaultVal "";
            if($current_sample){
                $current_sample += ",";
            }

            $average = $current_sample.Split(",") | select @{N='Value';E={ 
                $Item = $_.Split("=");
            }}

            New-ItemProperty -Path $CounterPath -Name $DateStr -Value ($current_sample + $RegValue) -PropertyType "String" -Force;
        }
    } catch {
        $ErrorMessage = $_.Exception.Message;    
    }


    Try{
        If($NoteObject){
            $CounterDB = Open-AuditDatabase -Path $CounterDatabase;
            
            $Entries = $CounterDB.GetEntries("$ProfileId");
            $CurrentEntry = $Entries | where {$_.CounterId -eq $CounterId -and $_.Date -eq $DateStr};
            If(($CurrentEntry | measure).Count -gt 0){
                $CurrentEntry.Counter += $NoteObject.Counter;
            } Else{
                $CounterDB.AddEntries("$ProfileId",$NoteObject);
            }       
            $CounterDB.Commit($true);
            $CounterDB.Close();
        }
        return $true;
    } catch {
        $ErrorMessage = $_.Exception.Message;
        
    }
    return $false;
}

$Profiles = Get-InstalledAirWatchProfileFiles -Path $profile_path -FileExtension "counters" -ModuleName "PollCounters"
$AliasObjects = @();
ForEach($Profile in $Profiles){
        
    $Date = (Get-Date).ToString("yyyy-MM-dd");
    If(!($Profile.ProfileObject)){
        Continue;
    }
    $ProfileId = $Profile.ProfileId;
    $Counters = $Profile.ProfileObject | where Counter;
    $Settings = $Profile.ProfileObject | where {$_.Counter -eq $null} | Select -First 1;

    $CounterSet = ($Counters | select Counter).Counter
    
    $SampleTime = 300;
    If($Settings.SampleTime){
        $SampleTime = $Settings.SampleTime;
    }

    #**************************************
    # PROFILE SCHEDULER CONFIG
    #**************************************
    $Sample = $true;
    $Transmit = $true;

    $LastScanReg = "$ProfileId`_LastScan"
    $NextScanReg = "$ProfileId`_NextScan"
    $LastTransmitReg = "$ProfileId`_LastTransmit"
    $NextTransmitReg = "$ProfileId`_NextTransmit"
    If($Settings.ScanInterval){
        $ScanInterval = $Settings.ScanInterval;
        $NextScanTime = Get-NextIntervalTime -RegKey $InstallPath -RegLastTime $LastScanReg -Interval $ScanInterval    
        $Sample = !($NextScanTime -gt 0)    
    }

    If($Settings.TransmitInterval){
        $TransmitInterval = $Settings.TransmitInterval;
        $NextTransmitTime = Get-NextIntervalTime -RegKey $InstallPath -RegLastTime $LastTransmitReg -Interval $TransmitInterval   
        $Transmit = !($NextTransmitTime -gt 0)     
    }


    $CurrentAliasObjects = @();
    If($Sample){ 
        #**************************************
        # SAMPLE SECTION
        #**************************************
        $CounterGet = Get-Counter -Counter $CounterSet -SampleInterval $SampleTime;
        foreach($myCounter in $CounterGet.CounterSamples){
            $counterPath = $myCounter.Path;


            #**************************************
            # Section to make formatting easy 
            #**************************************
            $counterBase = "";
            If($counterPath -match (".*\\([^\\]*)$")){
                If($Matches[1]){
                    $Matches[1];
                }
            }
            $CurrentCounter = $Counters | where {$counterPath -like ("*" + $_.Counter)};
            $counterid = $CurrentCounter.CounterId; 
            If(!($counterid)){
                If($counterBase){
                    If($counterBase -match "([\%\#]\s|^)(.*)"){
                        $counterid = $Matches[2].Replace("`s","_");
                        $CurrentCounter | Add-Member -MemberType NoteProperty -Name "CounterId" -Value $counterid
                    }
                } Else{
                    Continue;
                }
            }
            
            If(!($CurrentCounter.CounterName)){
                If($counterBase){
                    $CounterName = $Counter
                } ElseIf($CounterId){
                    $CounterName = $CounterId
                } Else{
                    Continue;
                }
                $CurrentCounter | Add-Member -MemberType NoteProperty -Name "CounterName" -Value $CounterName
            }

            $Unit = $CurrentCounter.ValueType;
            If(!($Unit)){
                If($myCounter.CounterType -Like "Average*"){
                    $Unit = "%"
                }
                $CurrentCounter | Add-Member -MemberType NoteProperty -Name "ValueType" -Value "%"
            }

            $timestamp = [datetime]$myCounter.Timestamp;
            $timeRegStr = (($timestamp.Hour * 60) + $timestamp.Minute).ToString();
            $timeNoteStr = $timestamp.ToString("HH:mm:ss");
            $rawValue = $myCounter.CookedValue;
            $rawValue = '{0:N1}' -f $myCounter.CookedValue;
            $currentCounterRegValue = "'$TimeRegStr'='$rawValue$Unit'";
            
            If($Unit -eq "%"){
                $myValue = '{0:N2}' -f ($rawValue / 100);
            }
            $currentCounterNoteValue = $myValue;

            $NoteObj = New-Object -TypeName PSCustomObject -Property @{"CounterId"=$CounterId;"Date"=$Date;"Counter"=@(
                    New-Object -TypeName PSCustomObject -Property @{"Time"=$timeNoteStr;"Value"=$currentCounterNoteValue}
             )};

            Set-StoredCounter -ProfileId $ProfileId -CounterId $counterid -DateStr $Date -RegValue $currentCounterRegValue -NoteObject $NoteObj;
        }
        $Now =  (Get-Date).ToString();   
        $SetLastScanTime = New-ItemProperty -Path $InstallPath -Name $LastScanReg -Value $Now -Force;
    }

    If($Transmit){     
        $CounterDB = Open-AuditDatabase -Path $CounterDatabase;
        $Entries = $CounterDB.GetEntries($ProfileId);

        $Entries = $Entries | where {(Get-Date).Subtract([datetime]$_.Date).TotalDays -lt 10};

        $Computations = $Entries | select *, @{N='Measure';
            E={ ($_.Counter | select Value).Value | Measure -Average -Maximum -Minimum }} |
            select *, @{N='AVG';E={$_.Measure.Average}}, @{N='MIN';E={$_.Measure.Minimum}}, 
                @{N='MAX';E={$_.Measure.Maximum}}, @{N='Count';E={$_.Measure.Count}} -ExcludeProperty Measure;

        $CounterDB.Commit($true);
        $CounterDB.Close();
        #**************************************
        # TRANSMIT SECTION
        #**************************************
        $ValidTypes = @("CustomAttributes","Note")
        ForEach($Counter in $Counters){
            $CounterId = $Counter.CounterId;
            $CounterName = $Counter.CounterName;
            $UID = "$ProfileId`_$CounterId"
            $Type = "CustomAttributes";
            If($Counter.Type){
                If($Counter.Type -in $ValidTypes){
                    $Type = $Counter.Type;
                }
            }

            $CurrentComputations = $Computations | where {$_.CounterId -eq $CounterId}

            If($Type -eq "CustomAttributes"){
                $CounterPath = "$InstallPath\$UID"
                $CurrentAuditItems =(Get-ItemProperty -Path $CounterPath).PSObject.Properties | 
                    where {$_.Name -match "2[0-9]{3}\-[0-1]{1}[0-9]{1}\-[0-3]{1}[0-9]{1}"} |
                    select *,@{N='Date';E={Try{[datetime]$_.Name} Catch { $null }} } | 
                    where {$_.Date -and $_.Value} |
                    select Name, Value, Date;
                
                $CurrentAuditItems | where {(Get-Date).Subtract($_.Date).Tota -gt 10} | % {
                    Try{ Remove-ItemProperty -Path $CounterPath -Name $_.Name -Force -ErrorAction Stop }
                    Catch{}
                }

                $Multiplier = 1;
                $Unit = "";
                If($Counter.ValueType){
                    If($Counter.ValueType -eq "%"){
                        $Multiplier = 100;
                        $Unit = "%";
                    }   
                }

                $CurrentAuditItems | % {
                    $CurrentDate = $_.Name;
                    $Computation = $CurrentComputations | where {$_.Date -eq $CurrentDate};
                    $AliasObjects += @((New-CustomVariableObj -Path $counterPath -ValueName $Date -Alias "Performance.$CounterName ($Date) Data"),
                        (New-CustomVariableObj -Path $counterPath -ValueName "$Date`_AVG" -Alias "Performance.$CounterName ($Date) AVG" -Value (
                        ("{0:N1}" -f ($Computation.AVG * $Multiplier)).ToString() +  "$Unit")));
                }
            } ElseIf($Type -eq "Note"){
                $NoteFormat = "List";
                $SupportedNoteFormats = @("List","Json","Csv");
                
                If($Counter.NoteFormat){
                    #Only supports List or Json currently
                    If($Counter.NoteFormat -in $SupportedNoteFormats){
                        $NoteFormat = $Counter.NoteFormat;
                    }
                }
                
                If($CurrentComputations){
                    If($NoteFormat -eq "List"){
                        $Note = $CurrentComputations | Select CounterId, Date, AVG, 
                            @{N='Counters';E={ $_.Counter | Out-String }} -ExcludeProperty Counter | Format-List | Out-String;
                    } ElseIf($NoteFormat -eq "Json"){
                        $Note = ConvertTo-Json $CurrentComputations -Depth 10 -Compress;
                    } ElseIf($NoteFormat -eq "Csv"){
                        $Note = ($CurrentComputations | Select -Property CounterId, Date -ExpandProperty Counter |
                            Select CounterId, Date, Time, Value) | ConvertTo-Csv;
                    }
                    Set-DeviceNote -NoteName "$UID" -Note $Note
                }
            }
        }
    }
}

$AliasRegPath = "SOFTWARE\AIRWATCH\InventorySettings\Counters"

Set-CustomVariables -ProfileName "PollCounters" -AliasObjects $AliasObjects -Rebuild $true -DisableAudit;