<#
    File: ProfileManagement.psm1
    Author: cbradley@vmware.com
#>

#==========================Header=============================#
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Reg";
}

Unblock-File "$current_path\Helpers.psm1"
$LocalHelpers = Import-Module "$current_path\Helpers.psm1" -ErrorAction Stop -PassThru -Force;

$shared_path = $Global:shared_path;

$GlobalModules = @();
$GlobalImporter = @("$shared_path\Database-Management.psm1", 
    "$shared_path\AirWatchAPI.psm1","$shared_path\Utility-Functions.psm1")
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$log_path\SmarterGroups.log"; 

$LocalCacheDBPath = "$current_path\Profiles\InstallList.db";
$DeviceNotesDBPath = "$current_path\Profiles\DeviceNotesV2.db";


Function Add-AirWatchUser{
      
    $bulk_items = @"
{
  "LocationGroupId":570,
  "UserName":"mandrew",
  "Status":true,
  "SecurityType":1
}
"@
    $getProfilesEndpoint = "api/system/users/adduser"
    
    
    $profiles_request = Invoke-AWApiCommand -Endpoint $getProfilesEndpoint -Method POST -ApiVersion 2 -Data $bulk_items
    


    return $profile_request;
}


Function Get-AssignedAirWatchProfiles{
    param([switch]$LocalLookupOnly, [switch]$APILookupOnly)
    
    $LocalCacheDB = Open-AuditDatabase -Path $LocalCacheDBPath -Encrypted;
    
    $getProfilesEndpoint = "api/mdm/devices/{DeviceId}/profiles"
    $Profiles = @();

    If(!$LocalLookupOnly.IsPresent){
        $profiles_request = Invoke-AWApiCommand -Endpoint $getProfilesEndpoint
    }
    If($profiles_request.DeviceProfiles){
        $Profiles = $profiles_request.DeviceProfiles | Select Name,Description,Status,CurrentVersion,AssignmentType,@{N='Id';E={$_.Id.Value}};
        $result = $LocalCacheDB.SetEntries("Profiles", $Profiles);
        if($result){
            $LocalCacheDB.Commit($true);
        }
    } ElseIf(!$APILookupOnly.IsPresent) {
        $Profiles = $LocalCacheDB.GetEntries("Profiles");
    } ElseIf($APILookupOnly.IsPresent){
        $Profiles = $profiles_request;
    }
    $LocalCacheDB.Close();
    return $Profiles;
}

Function Get-InstalledAirWatchProfileFiles{
    param($Path, $FileExtension, $ModuleName)
    $ProfileResults = @();
    $ValidProfileStatus = @(3,6);

    $ProfileCache = Get-AssignedAirWatchProfiles -LocalLookupOnly;

    $Profiles = Get-ChildItem -Path $Path -Filter "*.$FileExtension"
    Write-Log2 -Path $logLocation -Message ("Number of files found: " + ($Profiles | measure).Count)

    
    $AuditReg = @{};
    $AuditAlais = @{};
    ForEach($Profile in $Profiles){
        $DefaultStatus = "";
        $ProfileId = $Profile.BaseName;
        $ProfileName = $ProfileId;
        If($ProfileId -match "[1-9]{1}[0-9]{0,9}" -and $ProfileCache){     
            $ProfileNameSearch = $ProfileCache | where {$_.Id -eq $ProfileId};
            If($ProfileNameSearch){
                $ProfileName = $ProfileNameSearch.Name;
                If($ProfileNameSearch.Status -notin $ValidProfileStatus){
                    $DefaultStatus = "Removed";
                }
            }
        }

        $ProfileAuditObj = New-Object -TypeName PSCustomObject -Property  @{"ValueName"="$ProfileId";"Alias"="$ModuleName.$ProfileName";"Value"=$DefaultStatus};
        If($DefaultStatus -eq "Removed"){
            #Remove-Item $Profile.FullName -Force;
            $ProfileResultObj = New-Object -TypeName PSCustomObject -Property @{"ProfileId"="$ProfileId";"ProfileResult"=$ProfileAuditObj;"ProfileObject"=""};
            Write-Log2 -Path $logLocation -Message "Profile detected as removed - reporting back to management module";
            $ProfileResults += $ProfileResultObj;
            Continue;
        }
        Try{
            $ProfileJsonObj = ""
            $ReadProfile = [IO.File]::ReadAllText($Profile.FullName);
            If(!($ReadProfile.Contains("`s"))){
                Write-Log2 -Path $logLocation -Message ("Getting encrypted file: " + $Profile.FullName)
                $Unencrypted = ConvertFrom-EncryptedFile -FileContents $ReadProfile
                If($Unencrypted -notlike "Error: *"){
                    $ProfileJsonObj = ConvertFrom-Json -InputObject $Unencrypted    
                } Else{
                    $ProfileAuditObj.Value = $Unencrypted;
                }
               
            } Else{
                $ProfileJsonObj = ConvertFrom-Json -InputObject $ReadProfile
            }
            
        } Catch{
            $ErrorMessage = $_.Exception.Message;
            Write-Log2 -Path $logLocation -Message ("Error converting JSON: " + $ErrorMessage)
            $ProfileAuditObj.Value = "Error converting JSON: " + $ErrorMessage
        }
        $ProfileResultObj = New-Object -TypeName PSCustomObject -Property @{"ProfileId"="$ProfileId";"ProfileResult"=$ProfileAuditObj;"ProfileObject"=$ProfileJsonObj};
        $ProfileResults += $ProfileResultObj; 
    }
    return $ProfileResults;
}

Function Invoke-UninstallPowershellFile{
    param([string]$Filename)
    $removeFile = $false
    Try{
        $RawUninstallPS = [IO.File]::ReadAllText($Filename);
        $UninstallPS = ConvertFrom-EncryptedFile $RawUninstallPS;
        If($UninstallPS -like "Error*"){
            return $false;
        }
        $result = (iex $UninstallPS);
        Remove-Item $Filename;
        return $true;
    } Catch{
        $ErrorMessage = $_.Exception.Message;
        Write-Log2 -Path $logLocation "An error has occured. Error: $ErrorMessage" -Level Error
        $Results[$ProfileId] = "An error has occured. Error - $ErrorMessage"
    }
    Remove-Item $Filename;
    return $true;
}


Function Get-StringHash([String]$String,$HashName = "MD5") 
{ 
    $StringBuilder = New-Object System.Text.StringBuilder 
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
    [Void]$StringBuilder.Append($_.ToString("x2")) 
    } 
    $StringBuilder.ToString() 
}

Function Remove-AllNotes{
    $deviceNotes = "api/mdm/devices/{DeviceId}/notes"
    $Today = (Get-Date).ToString("MM-dd-yyyy");
       
    #Designate note endpoints
    $MyCurrentNote = $null;
    $CurrentNotes = Invoke-AWApiCommand -Endpoint $deviceNotes;
    If($CurrentNotes -Like "The remote name could not be resolved*"){
        Write-Log2 -Path $logLocation -Message "MachineOffline" -Level Warn
        return $false;
    }

    ForEach($CurrentNote in $CurrentNotes.DeviceNotes){
        $NoteId = $CurrentNote.Id;
        $DeleteNote = Invoke-AWApiCommand -Endpoint "$deviceNotes/$NoteId" -Method "DELETE";
        If($DeleteNote){

        }
    }
}


Function Set-DeviceNotes{
    param($ProfileId, $SystemId, $Notes)
    #Set PurgeTime in Days to purge archived data
    $deviceNotes = "api/mdm/devices/{DeviceId}/notes"
    $Today = (Get-Date).ToString("MM-dd-yyyy");
       
    #Designate note endpoints
    $MyCurrentNote = $null;
    $CurrentNotes = Invoke-AWApiCommand -Endpoint $deviceNotes;
    If($CurrentNotes -Like "The remote name could not be resolved*" -or $CurrentNotes -Like "Unauthorized"){
        Write-Log2 -Path $logLocation -Message "MachineOffline" -Level Warn
        return $false;
    }

    
    $DeviceId = "";
    $DeviceId = $Global:DeviceId;

    #Open local DB to map NoteIds
    $LocalCacheDB = Open-AuditDatabase -Path $DeviceNotesDBPath;
    $AllDBIDs = (($LocalCacheDB.DB.Profile | Select Entries).Entries | Select Id).Id

    $PurgeNotes = $CurrentNotes.DeviceNotes | Where {$_.Id -notin $AllDBIDs} | Select @{N='Name';E={$_.Id}}, @{N='Note';E={""}},
                @{N='DatabaseEntry';E={New-Object -TypeName PSCustomObject -Property @{'Id'=$_.Id}}}, @{N='ApiEntry';E={"Delete"}};

    $ProfileEntries = $LocalCacheDB.GetEntries("$ProfileId#$SystemId");

    $CurrentDBIds = ($ProfileEntries | Select Id).Id;

    $NoteObjects = @();
    $NoteObjects += $Notes | select *, @{N='DatabaseEntry';E={
            $ProfileEntry = $ProfileEntries | Where Name -eq $_.Name.Name
            If(($ProfileEntry  | measure).Count -gt 0){
                $ProfileEntry 
            } Else {
                $null
            }
        }},
        @{N='ApiEntry';E={
            $DBEntry = $ProfileEntries | Where Name -eq $_.Name.Name
            If(($DBEntry | measure).Count -gt 0){
                $APIEntry = $CurrentNotes.DeviceNotes | Where {$_.Id -eq $DBEntry.Id};
                $APIEntry
            } Else {
                $null
            }
        }};
 
    $CurrentIds = ($NoteObjects | Select @{N='Id';E={$_.DatabaseEntry.Id}}).Id;
 
    $NoteObjects += $ProfileEntries | Where {$_.Id -notin $CurrentIds} | 
            Select Name, @{N='Note';E={""}},@{N='DatabaseEntry';E={$_}},
                @{N='ApiEntry';E={"Delete"}};

    If(($PurgeNotes | Measure).Count){
        $NoteObjects += $PurgeNotes
    }

    ForEach($CurrentNote in $NoteObjects){      
        #Get a hash of the note string so we can do a comparison
        $NoteHash = (Get-StringHash -String $CurrentNote.Note);

        $NoteObj = New-Object -TypeName PSCustomObject -Property @{"Note"=$CurrentNote.Note};
           
        $Method = "";

        #If we do not having a matching DB Entry
        If($CurrentNote.DatabaseEntry -eq $null){      
            $CurrentNote.DatabaseEntry = New-Object -TypeName PSCustomObject -Property @{"Name"=$CurrentNote.Name.Name;"Id"=-1;"NoteHash"=$NoteHash;}
            $NoteObj = $NoteObj | Select *, @{N='CreationDate';E={$Now}} 
            $Method = "Post"    
        } Else {
            If(($CurrentNote.DatabaseEntry.Id -eq -1) -and ($CurrentNote.ApiEntry -ne $null)){
                $CurrentNote.DatabaseEntry.Id = $CurrentNote.ApiEntry.Id;
            }

            If($CurrentNote.DatabaseEntry.Id -ne -1){
                If(($CurrentNote.ApiEntry -ne "Delete")){
                    If($CurrentNote.DatabaseEntry.NoteHash -ne $NoteHash){
                        $NoteObj = $NoteObj | Select *, @{N='DeviceId';E={$DeviceId}}, @{N='Id';E={$MyNoteEntry.Id}};
                        $CurrentNote.DatabaseEntry = $NoteHash;
                        $NoteId = "/" +  $CurrentNote.DatabaseEntry.Id;
                        $Method = "Put";
                    }
                } Else{
                    $NoteId = "/" + $CurrentNote.DatabaseEntry.Id;
                    $Method = "DELETE";
                    $NoteObj = "";
                }
            } 
        }

        $NoteData = ConvertTo-Json $NoteObj;
   
        If($Method){
            $SetNote = Invoke-AWApiCommand -Endpoint "$deviceNotes$NoteId" -Method $Method -Data $NoteData;
            Try{
                If($SetNote.Value){
                    If($Method -eq "Post"){
                        $CurrentNote.DatabaseEntry.Id = $SetNote.Value;
                        $CurrentNote.DatabaseEntry.NoteHash = $NoteHash;
                    } ElseIf($Method -eq "Delete"){

                    }
                } ElseIf($Method -eq "DELETE" -and $SetNote.StatusCode){
                    If($SetNote.StatusCode -eq 200 -or $SetNote.StatusCode -eq 404){
                         $CurrentNote.ApiEntry = "Deleted";
                    }
                }
            } Catch{
                $ErrorMessage = $_.Exception.Message;
            }
        }#>
    }
    $NoteEntries = ($NoteObjects | Where {$_.DatabaseEntry -and $_.ApiEntry -ne "Deleted"} | Select DatabaseEntry).DatabaseEntry
    $Update = $LocalCacheDB.SetEntries("$ProfileId#$SystemId",$NoteEntries);
                
    If($LocalCacheDB.Status -eq 2){
        $LocalCacheDB.Commit($true);
    }
    $LocalCacheDB.Close();
    return $true;
}

Function Set-DeviceNote{
    param([string]$Note, $NoteName, [switch]$Historical)
    #Set PurgeTime in Days to purge archived data
    $deviceNotes = "api/mdm/devices/{DeviceId}/notes"
    If($Historical.IsPresent){
        $Today = (Get-Date).ToString("MM-dd-yyyy");
        $PurgeTime = 10;
    }
    #Designate note endpoints
    $MyCurrentNote = $null;
    $CurrentNotes = Invoke-AWApiCommand -Endpoint $deviceNotes;
    If($CurrentNotes -Like "The remote name could not be resolved*"){
        Write-Log2 -Path $logLocation -Message "MachineOffline" -Level Warn
        return $false;
    }
    
    $DeviceId = "";
    $DeviceId = $Global:DeviceId;

    #Open local DB to map NoteIds
    $LocalCacheDB = Open-AuditDatabase -Path $LocalCacheDBPath -Encrypted;
    $NoteEntries = $LocalCacheDB.GetEntries("NoteRef");
      
    #Get a hash of the note string so we can do a comparison
    $NoteHash = (Get-StringHash -String $Note);

    $Now = (Get-Date).ToString();
    $NoteObj = New-Object -TypeName PSCustomObject -Property @{"Note"=$Note};

    #Get the note out of the local entries
    $MyNoteEntry = $NoteEntries | where {$_.Name -eq $NoteName}
 
    If(!($CurrentNotes.DeviceNotes)){
        $CurrentNotes = @();       
    } Else{
        If($MyNoteEntry){
            $MyCurrentNote = $CurrentNotes.DeviceNotes | Where {$_.Id -eq $MyNoteEntry.Id}
        }
    }

    #Alternate search
    If((!($MyCurrentNote)-and $CurrentNotes) -and ($MyNoteEntry)){
        $CurrentNoteHashes = $CurrentNotes.DeviceNotes | Select Id, @{N='NoteHash';E={Get-StringHash -String $_.Note}}
        $CurrentNoteSearch = $MyNoteEntry | Where { $_.NoteHash -in ($CurrentNoteHashes | Select NoteHash).NoteHash };
        If(($CurrentNoteSearch | Measure).Count -gt 0){
            $MyCurrentNote = $CurrentNoteSearch | Select -First 1
            $MyNoteEntry.Id = $MyCurrentNote.Id
            $Update = $Update = $LocalCacheDB.SetEntries("NoteRef",$MyNoteEntry,@("Name"),@("Hash","Id"),$false);
        }
    }

    $Method = "";
    #If we do not having a matching ID in the DB OR their are no notes for the device 
    If(!($MyNoteEntry) -or !($MyCurrentNote)){      
        $MyNoteEntry = New-Object -TypeName PSCustomObject -Property @{"Name"=$NoteName;"Id"=-1;"NoteHash"=$NoteHash;}
        $NoteObj = $NoteObj | Select *, @{N='CreationDate';E={$Now}} 
        $Method = "Post"    
    } Else {
        If(($MyNoteEntry.Id -ne -1) -and ($MyCurrentNote)){
            $NoteObj = $NoteObj | Select *, @{N='DeviceId';E={$DeviceId}}, @{N='Id';E={$MyNoteEntry.Id}};
            $MyNoteEntry.NoteHash = $NoteHash;
            $NoteId = "/" + $MyNoteEntry.Id;
            $Method = "Put";
        }
    }
    $NoteData = ConvertTo-Json $NoteObj;
   
    If($Method){
        $SetNote = Invoke-AWApiCommand -Endpoint "$deviceNotes$NoteId" -Method $Method -Data $NoteData;
        Try{
            If($SetNote.Value){
                If($Method -eq "Post"){
                    $MyNoteEntry.Id = $SetNote.Value;
                    $MyNoteEntry.NoteHash = $NoteHash;
                }
            }
            If(($NoteEntries | where {$_.Name -eq $MyNoteEntry.Name} | measure).Count -gt 0){              
                $Update = $LocalCacheDB.SetEntries("NoteRef",$MyNoteEntry,@("Name"),@("Hash","Id"),$false);
            } Else {
                $LocalCacheDB.AddEntries("NoteRef", $MyNoteEntry);  
            }

        } Catch{
            $ErrorMessage = $_.Exception.Message;
        }
    }
    If($LocalCacheDB.Status -eq 2){
        $LocalCacheDB.Commit($true);
    }
    $LocalCacheDB.Close();
    return $true;
}

Function Get-NextIntervalTime{
    param([string]$RegKey, [string]$RegLastTime, [string]$Interval)
    If($RegKey.Contains("HKLM:\")){
        $RegKey = $RegKey.Replace("HKLM:\","")        
    } 

    #Retrieve the last scan time
    $Now = (Get-Date).ToString();
    $CurrentLastScan = [datetime](Get-ItemPropertyValueSafe -Path "HKLM:\$RegKey" -Name $RegLastTime -DefaultVal $Now);
   
    $Scheduled = ConvertTo-DateTime -Time $Interval -TimeSpanBase $CurrentLastScan

    #Get the next scan time in seconds
    $NextScanTime = $Scheduled.Subtract((Get-Date)).TotalSeconds;
   
    #$ProfileResults += (New-CustomVariableObj -Path "HKLM:\$CustomSettingsReg" -ValueName $NextScanReg -Value (
    #    ("{0:N2}" -f $NextScanTime).ToString() + "s" ) -Alias "CustomSettings.$ProfileName` Next Scan");

    return $NextScanTime
}


Export-ModuleMember -Function Invoke-UninstallPowershellFile, Get-InstalledAirWatchProfileFiles, Get-AssignedAirWatchProfiles, Set-DeviceNote, Set-DeviceNotes, Get-NextIntervalTime, Remove-AllNotes