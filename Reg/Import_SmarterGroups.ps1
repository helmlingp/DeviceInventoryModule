<#
    File: Import_SmarterGroups.ps1
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

if(Test-Path "$shared_path\api-debug.config"){
    $Debug = 1;
}

$GlobalModules = @();
$GlobalImporter = @("$current_path\CustomSettingsLib.psm1", "$current_path\SmarterGroupsLib.psm1", 
    "$current_path\ProfileManagement.psm1", "$shared_path\AirWatchAPI.psm1","$shared_path\Utility-Functions.psm1")
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$log_path\SmarterGroups.log"; 

$SmarterGroupsRegKey = "HKLM:\Software\AirWatch\ProductProvisioning\SmarterGroups";

#==========================Body=============================#
$GetProfiles = Get-AssignedAirWatchProfiles -APILookupOnly;
If($GetProfiles -Like "The remote name could not be resolved*"){
    Write-Log2 -Path $logLocation -Message "MachineOffline" -Level Warn
    return;
}


$OrganizationGroupId = $Global:OrganizationGroupId;
$deviceid = $Global:DeviceId;

$tags_endpoint = "api/mdm/tags/search?organizationgroupid=$OrganizationGroupId&name=";
$device_endpoint = "api/mdm/devices/$deviceid/";
$add_tag_endpoint = "api/mdm/tags/addtag";
$addDeviceEndpoint = "api/mdm/tags/{tagid}/adddevices";
$removeDeviceEndpoint = "api/mdm/tags/{tagid}/removedevices";
$change_og_endpoint = "api/mdm/devices/$deviceid/commands/changeorganizationgroup/";
$og_search_endpoint = "api/system/groups/search";
$getApplicationsEndpoint = "api/mdm/devices/$deviceid/apps"
$getProfilesEndpoint = "api/mdm/devices/$deviceid/profiles"

$TagCache = Get-DeviceTags;

$bulk_items = @"
{
  "BulkValues": {
    "Value": [
      $deviceId
    ]
  }
}
"@

$tag_format = @"
{
  "TagAvatar":"{tagname}",
  "TagName": "{tagname}",
  "TagType": 1,
  "LocationGroupId": $OrganizationGroupId
}
"@


$ObjectCache = @{};
$SmarterGroupsErrors = @();
$SmarterGroupsConfigs = @{};
    


if($GetProfiles){
    if(!$ObjectCache.ContainsKey("Profiles")){     
        $ObjectCache.Add("Profiles", $GetProfiles);
    }
}

$Profiles = Get-InstalledAirWatchProfileFiles -Path "$current_path\Profiles" -FileExtension "map" -ModuleName "SmarterGroups";

#Installed Profile Logic
$ProfileResults = @();
ForEach($Profile in $Profiles){
    $ProfileId = $Profile.ProfileId;

    $ProfileResults += $Profile.ProfileResult;
    $CurrentResult = ($ProfileResults | where {$_.ValueName -eq $ProfileID});

    if($Profile.ProfileResult.Value -like "Error*"){
        Write-Log2 -Path $logLocation ("An error has occured: " + $Profile.ProfileResult.Value) -Level Warn
        continue
    } elseif($Profile.ProfileResult.Value -like "Removed*"){
        
    }elseif(!($Profile.ProfileObject.TagMaps)){
        Write-Log2 -Path $logLocation "An error has occured. Error: JSON not in correct format.  The item, TagMaps, is missing." -Level Error
        $CurrentResult.Value = "An error has occured. Error- JSON not in correct format.  The item, TagMaps, is missing."
        continue
    }

    

    $DG_Object = $Profile.ProfileObject;

    $CommitTxt = "UPDATES COMMITED";
    $CommitUpdates = $true;
    $Debug = $false;
    $Schedule = 0;

    #Check to see if Debug logging flag has been specified
    If($DG_Object.CommitUpdates){
        $CommitUpdates = $DG_Object.CommitUpdates;
        $CommitTxt = "UPDATES NOT COMMITTED";
    }

    #Check to see if Debug logging flag has been specified
    If($DG_Object.Debug){
        $Debug = $DG_Object.Debug;
    }

    #Check to see if file has unique scheduled
    $ScheduledItem = $null;
    If($DG_Object.Schedule){
        $ScheduledItem = $DG_Object.Schedule;
        
        $CurrentLastScan = [datetime](Get-ItemPropertyValueSafe -Path $SmarterGroupsRegKey -Name ($ProfileId + "_LastScan") -DefaultVal (Get-Date).ToString());

        $Scheduled = ConvertTo-DateTime -Time $ScheduledItem -TimeSpanBase $CurrentLastScan

        $NextScanTime = $Scheduled.Subtract((Get-Date)).TotalSeconds;
        $ProfileResults += (New-CustomVariableObj -Path $SmarterGroupsRegKey -ValueName "$ProfileId`_NextScan" -Value (
                ("{0:N2}" -f $NextScanTime).ToString() + "s" ) -Alias "SmarterGroups.$ProfileName` Next Scan")
        if($NextScanTime -gt 0){
            $ProfileResults = @() + ($ProfileResults | where {$_.ValueName -ne $ProfileId});
            continue;
        }

    }


    $ResultProp = @{"Added" = @();"Removed" = @();"OrgGroup" = @();"InDatabase"=@();"AlreadyAdded"=@()};
    $ResultObj = New-Object -TypeName PSCustomObject -Property $ResultProp;; 
    ForEach($Tag in $DG_Object.TagMaps){
          
        $tag_id = "";
        $ogid = "";
        #*********************************************************************
        # Get the tagid or organizationgroupid
        #      
        If($Tag.TagName){
            #Name of the tag
            $name = $Tag.TagName;

            $tags_json = Invoke-AWApiCommand -Endpoint ("$tags_endpoint" + $Tag.TagName) -Header $Headers
            If(($tags_json.Tags | measure).Count -gt 0){
               $tag_id = $tags_json.Tags[0].Id.Value;
            } 

            If(!$tag_id) {               
                #Add tag
                $body = $tag_format.Replace("{tagname}", $Tag.TagName)
                $add_tag = Invoke-AWApiCommand -Method Post -Endpoint $add_tag_endpoint -Headers $Headers -Data $body; 
                if($add_tag.Value){
                    $tag_id = $add_tag.Value;
                }
            }

        } ElseIf ($Tag.NewOrganizationGroup -or $Tag.NewOrganizationGroupID -or $Tag.NewGroupId) {
            If($Tag.NewOrganizationGroupId){
                $ogid = $Tag.NewOrganizationGroupId;
            } ElseIf ($Tag.NewOrganizationGroup){
                $OG_Search = Invoke-AWApiCommand -Endpoint ("$og_search_endpoint`?name=" + $Tag.NewOrganizationGroup ) -ApiVersion 2;
                If($OG_Search.OrganizationGroups){
                    $ogid = $OG_Search.OrganizationGroups[0].Id;
                }
            } ElseIf ($Tag.NewGroupId){
                $OG_Search = Invoke-AWApiCommand -Endpoint ("$og_search_endpoint`?groupid=" + $Tag.NewGroupId ) -ApiVersion 2;
                If($OG_Search.OrganizationGroups){
                    $ogid = $OG_Search.OrganizationGroups[0].Id;
                }
            }
        }
        
        $FinalResult = $false;
        #Process the results
        If($Tag.Type -eq "PowerShell"){   
            If($Debug){
                Write-Log2 -Path $logLocation -Message $Tag.PSLogic;
            }

            $PSResult = (Invoke-ExpressionSafe -Command $Tag.PSLogic -Debug $Debug);
            If($Debug){ Write-Log2 -Path $logLocation -Message ($PSResult | Format-List | Out-String); }
            
            #Error handling to ensure we have results
            If($PSResult -eq $null){
                Write-Log2 -Path $logLocation -Message "An error occured";
            } ElseIf($PSResult -like "*Error*"){
                Write-Log2 -Path $logLocation -Message "An error occured: $PSResult";
            }
            
            #Set the final result
            $FinalResult = $PSResult;
           
        } Elseif($Tag.Type -eq "AirWatch") {
            #Get Cached objects
            If($Tag.Triggers | where "Type" -eq "Application"){
                If(!$ObjectCache.ContainsKey("Application")){
                    $application_request = Invoke-AwApiCommand -Endpoint $getApplicationsEndpoint -Headers $Headers;
                    if($application_request.DeviceApps){
                        $ObjectCache['Application'] = $application_request.DeviceApps;
                    }
                }
            }
            If($Tag.Triggers | where "Type" -eq "Profile"){
                If(!$ObjectCache.ContainsKey("Profile")){
                    $profiles_request = Invoke-AwApiCommand -Endpoint $getProfilesEndpoint -Headers $Headers;
                    if($profiles_request.DeviceProfiles){
                        $ObjectCache['Profile'] = $profiles_request.DeviceProfiles;
                    }
                }
            }
            If($Tag.Triggers | where "Type" -eq "Device"){
                If(!$ObjectCache.ContainsKey("Device")){
                    $device_request = Invoke-AwApiCommand -Endpoint $device_endpoint -Headers $Headers;
                    if($device_request){
                        $ObjectCache['Device'] = $device_request;
                    }
                }
            }
            #Process the triggers
            $TriggerResults = Get-AWItemStatus -Cache $ObjectCache -Triggers $Tag.Triggers;
            If($TriggerResults -eq 0){
                $FinalResult = $true;
            }
        }

        If($CommitUpdates){
            $SetResults = Set-SmartGroupResults -Result $FinalResult -TagId $tag_id -NewOrganizationGroupId $ogid -TagCache $TagCache -IsStatic:($Tag.Static) -Debug:($Debug);
            If($SetResults -match "([^\:]*)\:([0-2])"){
                $Action = $Matches[1];
                $Change = $Matches[2];
                $Item =  $Tag.TagName;
                If(!($Tag.TagName)){
                    $Item = $OrganizationGroupId;
                }
                If($Change -eq 0){
                    $ResultObj."$Action" += $Item;
                } ElseIf($Change -eq 1){
                    $ResultObj.InDatabase += $Item;
                } ElseIf($Change -eq 2){
                    $ResultObj.AlreadyAdded += $Item;
                }
            }
        }
            
    }

    #If($Debug){
        Write-Log2 -Path $logLocation -Message "$CommitTxt"
        Write-Log2 -Path $logLocation -Message ($ResultObj | Format-List | Out-String)
    #}
    $CurrentResult.Value = "Added= " + $resultObj.Added.Count + ",Removed= " + $resultObj.Removed.Count + ",OGs Changed = " + $resultObj.OrgGroup.Count;
    $Now =  (Get-Date).ToString();   
    $SetLastScanTime = New-ItemProperty -Path $SmarterGroupsRegKey -Name ($ProfileId + "_LastScan") -Value $Now -Force;
}

$Now = (Get-Date).ToString("MM-dd-yyyy hh.mm.ss");
$LastScan = New-CustomVariableObj -Path $SmarterGroupsRegKey -Value $Now -ValueName "LastScanComplete" -Alias "SmarterGroups.LastScan"; 
$ProfileResults += $LastScan;
Set-CustomVariables -ProfileName "SmarterGroups" -KeyPath "Software\AirWatch\ProductProvisioning\SmarterGroups" -AliasObjects $ProfileResults -DisableAudit;