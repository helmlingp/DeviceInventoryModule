<#
    File: Import_CustomSettings.ps1
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
$GlobalImporter = @("$current_path\CustomSettingsLib.psm1", "$current_path\SmarterGroupsLib.psm1", 
        "$current_path\ProfileManagement.psm1","$shared_path\Utility-Functions.psm1")
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

$logPath = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$logPath\DeviceInventory.log";

$ProfilePath = "$current_path\Profiles";
If(!(Test-Path $ProfilePath)){
    New-Item -Path $ProfilePath -ItemType Directory -Force;
}

$CustomSettingsReg = "Software\AirWatch\ProductProvisioning\CustomSettings";

#==========================End Header=========================#

Function Apply-CustomVariables{
    #Get setup JSON
    $Debug = 0;    
    #Remove-AllNotes;
    #Get custom setting profile
    $Profiles = Get-InstalledAirWatchProfileFiles -Path "$current_path\Profiles" -FileExtension "settings" -ModuleName "CustomSettings";
   
    #Get count for result
    $NumProfiles = ($CustomSettingsProfiles | where {$_.ProfileResult.Value -eq ""} | measure).Count;
    $NumErrors = ($CustomSettingsProfiles | where {$_.ProfileResult.Value -like "Error*"} | measure).Count;

    Write-Log2 -Path $logLocation "$NumProfiles valid profiles found, and $NumErrors with errors.  Processing files now."
    
    #Remove-AllNotes;

    $ProfileResults = @();
    foreach($Profile in $Profiles){  
        $CmndletId = 0;
        $ProfileID = $Profile.ProfileId 

        $ProfileResults += $Profile.ProfileResult;
        $CurrentResult = ($ProfileResults | where {$_.ValueName -eq $ProfileID});
        $CurrentSystems = $Profile.ProfileObject;
        if($Profile.ProfileResult.Value -like "Removed*"){
            If(Remove-CustomSettingsProfile ){
                
            }     
        } elseif($Profile.ProfileResult.Value -like "Error*"){
            Write-Log2 -Path $logLocation ("An error has occured: " + $Profile.ProfileResult.Value) -Level Warn
             continue
        } elseif(!($CurrentSystems)){
            Write-Log2 -Path $logLocation "An error has occured. Error: JSON not in correct 
                format.  The item, Systems, is missing." -Level Error
            $CurrentResult.Value = "An error has occured. Error- JSON not in correct format. 
                The item, Systems, is missing."
            continue;
        } elseif($CurrentSystems.Systems -ne $null){
            $CurrentSystems = $CurrentSystems.Systems;
        }
        
        If(!($CurrentSystems.GetType().BaseType.Name -eq "Array")){
             Write-Log2 -Path $logLocation -Message "An error has occured. Error: 
                    JSON not in correct format." -Level Error
                continue
        }
                    
        foreach($SystemItem in $CurrentSystems){
            $Alias = "";
            $SystemName = "";
            $RegKey = "";
            if(!($SystemItem.Name) -or (!($SystemItem.CmndletMappings) -and !($SystemItem.Cmndlets))){
                Write-Log2 -Path $logLocation -Message "An error has occured. Error: 
                    JSON not in correct format." -Level Error
                continue
            } else {
                $CmndletMappings = $SystemItem.CmndletMappings;
                If(!($CmndletMappings) -and $SystemItem.Cmndlets){
                    $CmndletMappings = $SystemItem.Cmndlets;
                }

                $Alias = $SystemItem.Name + ".";
                $SystemName = $SystemItem.Name;
                $RegKey = "Software\\AirWatch\\InventorySettings\\$SystemName"; 
            }
            
            $NoteObjects = @();
            $CustomSettingsObjects = @();
            #*************Get the System settings*************
            $LastScanReg = "$ProfileId.$SystemName`_LastScan"
            $NextScanReg = "$ProfileId.$SystemName`_NextScan"
            If($SystemItem.Schedule){
                $ScheduledItem = $SystemItem.Schedule;

                #Retrieve the last scan time
                $Now = (Get-Date).ToString();
                $CurrentLastScan = [datetime](Get-ItemPropertyValueSafe -Path "HKLM:\$CustomSettingsReg" -Name $LastScanReg -DefaultVal $Now);

                $Scheduled = ConvertTo-DateTime -Time $ScheduledItem -TimeSpanBase $CurrentLastScan

                #Get the next scan time in seconds
                $NextScanTime = $Scheduled.Subtract((Get-Date)).TotalSeconds;
                $ProfileResults += (New-CustomVariableObj -Path "HKLM:\$CustomSettingsReg" -ValueName $NextScanReg -Value (
                        ("{0:N2}" -f $NextScanTime).ToString() + "s" ) -Alias "CustomSettings.$ProfileName` Next Scan");
                if($NextScanTime -gt 0){
                    $ProfileResults = @() + ($ProfileResults | where {$_.ValueName -ne $ProfileId});
                    continue;
                }
            }

            #***********End Section System settings***********
            ForEach($CmndletMap in $CmndletMappings){
                #*************Get the CmndletMapping settings*************
                #Support for Type at the Cmndlet level

                $SupportedNoteFormats = @("CustomAttribute","Note");
                $Type = "CustomAttribute"
                If($CmndletMap.Type){
                    $Type = $CmndletMap.Type;
                    If($Type -notin $SupportedNoteFormats){
                          Write-Log2 -Path $logLocation "Unsuported type" -Level Error
                    }
                }

                $SupportedNoteFormats = @("List","Json","Csv");
                $SupportedNoteHistory = @(0,1)
                If($Type -eq "Note"){
                    $NoteName = "";
                    #If we are storing a note, then we should determine the output of the Cmndlet
                    If(!($CmndletMap.NoteName)){
                        $CurrentResult.Value = "An error has occured. Error- JSON not in correct format. 
                             The item, Systems, is missing."
                        Continue;
                    }
                    $NoteName = "$ProfileID." + $CmndletMap.NoteName;

                    $NoteFormat = "List"
                    If($CmndletMap.NoteFormat){
                        #Only supports List or Json currently
                        If($CmndletMap.NoteFormat -in $SupportedNoteFormats){
                            $NoteFormat = $CmndletMap.NoteFormat;
                        }
                    } 

                    #Determines whether or not the system will store an audit trail
                    $NoteHistory = 0
                    If($CmndletMap.NoteHistory){
                        If($CmndletMap.NoteHistory -in $SupportedNoteHistory){
                            $NoteFormat = $CmndletMap.NoteHistory;
                        }
                    }
                }
                #**********End Section CmndletMapping settings*************

                If($Debug){ Write-Log2 -Path $logLocation -Message ("Commandlet =" + $CmndletMap.Cmdlet); }

                $Cmndlet = $CmndletMap.Cmndlet;
                If($Cmndlet -eq $null -and $CmndletMap.Cmdlet -ne $null){
                    $Cmndlet = $CmndletMap.Cmdlet;
                }

                $CmndletResults = Invoke-ExpressionSafe -Command $Cmndlet -Debug 1;

                If($Debug){ Write-Log2 -Path $logLocation -Message ($CmndletResults | Format-List | Out-String) }
                    
                $CustomSettingsItems = @();
                $ResultCount = 0;
                ForEach($CmndletResult in $CmndletResults){
                    if($CmndletMap.Name){
                        $Namespace = $CmndletMap.Name;
                    } Else { 
                        $Namespace = $SystemName;
                    }
                    $prefix = "";
                    if($Namespace.Contains("#")){       
                        $Namespace = $Namespace.Replace("#",$ResultCount.ToString());
                        $prefix = "$ResultCount.";
                    } elseif (($CmndletResults | measure).Count  -gt 1) {
                        $Namespace = $Namespace + $ResultCount.ToString();
                        $prefix = "$ResultCount.";
                    }

                    $PropertiesNew = @();

                    If($CmndletMap.Attributes){
                        $CustomAttributes = @() + $CmndletMap.Attributes;
                           
                        #Logic for attributes                      
                        $PropertiesNew += $CmndletResult.PSObject.Properties | Select * | 
                            Where {($_.Name -in $CustomAttributes) -or ($_.Name -and $CustomAttributes -eq "*")} | 
                            Select-Object -Property @{N='ValueName';E={$prefix + $_.Name}}, Value, 
                                @{N='Alias';E={"$Namespace." + $_.Name}}                                    
                    }

                    #Logic for handling custom format
                    If($CmndletMap.FormattedAttributes){
                        $PropertiesFormattedNew = $CmndletMap.FormattedAttributes.PSObject.Properties | % {
                            $Name = $_.Name;
                            $Expression = $_.Value;
                            If($Expression -match "^[A-z0-9_]*$"){
                                $Expression = "`$_." + $_.Value;
                            }
                            $ScriptBlock = [scriptblock]::Create( $Expression );
                            $PropertiesNew += $CmndletResult | Select-Object @{N="Value";E=$ScriptBlock},
                                @{N="ValueName";E={"$prefix$Name"}},@{N="Alias";E={"$Namespace.$Name"}};
                        }
                    }
                        
                    #Logic for mapping dictionary type values
                    If($CmndletMap.MappedValues){
                        $MappedValues = $CmndletMap.MappedValues.PSObject.Properties | % {
                            $Name = $Mappings.Name;
                            $CurrentItem = $PropertiesNew | where {$_.ValueName -eq "$prefix$Name"}
                            If($CmndletResult."$Name"){
                                $Val = $CmndletResult."$Name";
                                If($_."$Name"."$Val"){
                                    If(!($CurrentItem)){
                                        $PropertiesNew += (New-CustomVariableObj -ValueName "$prefix$Name" -Value $_."$Name"."$Val" -Alias "$Namespace.$Name");
                                    } Else {
                                        $CurrentItem.Value = $_."$Name"."$Val";
                                    }
                                }
                            }
                        }  
                    }

                    If($Type -eq "Note"){
                        $NotePrefix = "";
                        If($ResultCount -gt 0){
                            $NotePrefix = $ResultCount;
                        }

                        $NoteHashTable = @{};
                             
                        $NoteFormaterObject = New-Object -TypeName PSCustomObject;
                        $NoteFormater = $PropertiesNew | % {
                            $ValueName = $_.ValueName;
                            If($prefix -ne ""){
                                $ValueName = $_.ValueName.Replace("$prefix","");
                            }
                            $NoteFormaterObject | Add-Member -MemberType NoteProperty -Name $ValueName -Value $_.Value
                        }                       
                        $NoteObject = $NoteFormaterObject | 
                                Select-Object @{N='Name';E={"$NoteName"}},@{N='CmndletId';E={$CmndletId}},
                                              @{N='Type';E={$NoteFormat}},@{N='Value';E={$_}};
                        

                        $NoteObjects += $NoteObject;

                    } Else{
                        $CustomSettingsObjects += $PropertiesNew;
                    }
                    $ResultCount++;
                }
                $CmndletId++;
            }


            If(($NoteObjects | Measure).Count -gt 0){
                $NoteObjectGroups = ($NoteObjects | Group-Object Name, CmndletId | Select @{N='Name';E={$_.Group | Select -First 1}}, 
                    @{N='Note';E={
                        $val =  $_.Group.Value;
                        $type = $_.Group.Type | Select -First 1
                        If($type -eq "Json"){
                            ConvertTo-Json $val -Depth 10 -Compress
                        } ElseIf ($type -eq "Csv"){
                            $val |  ConvertTo-Csv -NoTypeInformation | Out-String
                        } Else {
                            $val | Out-String
                        }
                }});
              
                Set-DeviceNotes -ProfileId $ProfileID -SystemId $SystemName -Notes $NoteObjectGroups
            } Else{
                #Set registry values
                $SetCvResult = Set-CustomVariables -ProfileName $ProfileID -KeyPath $RegKey -AliasObjects $CustomSettingsObjects -RemoveDeletedEntries;
            }
        }

        #Finish up the script
        $Now =  (Get-Date).ToString();   
        $SetLastScanTime = New-ItemProperty -Path "HKLM:\$CustomSettingsReg" -Name $LastScanReg -Value $Now -Force;
        $CurrentResult.Value = "SUCCESS - $Now";
    }
    
    
    $LastScan = New-CustomVariableObj -Path "HKLM:\$CustomSettingsReg" -Value (date).ToString("MM-dd-yyyy hh.mm.ss") -ValueName "LastScanComplete" -Alias "CustomAttributes.LastScan"; 
    $ProfileResults += $LastScan;
    Set-CustomVariables -ProfileName "CustomSettings" -KeyPath $CustomSettingsReg -AliasObjects $ProfileResults -DisableAudit;
}

Apply-CustomVariables