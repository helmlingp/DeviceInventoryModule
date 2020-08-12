<#
#
#
#>
$logLocation = "C:\Temp\Logs\UserManagement.log";
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\UserManagement";
}

$InstallPath = "HKLM:\Software\AIRWATCH\ProductProvisioning";
$shared_path = "C:\Temp\Shared"
If(Test-Path $InstallPath){
    $getShared_path = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -eq "SharedPath") | Measure;
    If($getShared_path.Count -gt 0){
        $shared_path = Get-ItemPropertyValue -Path $InstallPath -Name "SharedPath";       
    }
} 

Unblock-File "$shared_path\Security-Functions.psm1"
$module = Import-Module "$shared_path\Security-Functions.psm1" -ErrorAction Stop -PassThru -Force;
Unblock-File "$shared_path\AirWatchAPI.psm1"
$apimodule = Import-Module "$shared_path\AirWatchAPI.psm1" -ErrorAction Stop -PassThru -Force;

$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$log_path\UserManagement.log"; 


#Set API content types
#$content_type = "application/json;version=1";
#$content_type_v2 = "application/json;version=2";

#$api_settings_obj = Get-AWAPIConfiguration;

#$Server = $api_settings_obj.ApiConfig.Server;
#$API_Key = $api_settings_obj.ApiConfig.ApiKey
#$Auth = $api_settings_obj.ApiConfig.ApiAuth;
#$OrganizationGroupId = $api_settings_obj.ApiConfig.OrganizationGroupId;
#$deviceid = $api_settings_obj.ApiConfig.DeviceId;

$device_endpoint = "/api/mdm/devices/{DeviceId}/";
$change_user_endpoint = "/api/mdm/devices/{DeviceId}/enrollmentuser/";
$user_search_endpoint = "/api/system/users/search";
$user_details_endpoint = "/api/system/users/";
$og_search_endpoint = "/api/system/groups/search";
$change_og_endpoint = "/api/mdm/devices/{DeviceId}/commands/changeorganizationgroup/";
$smartgroup_search = "/api/mdm/smartgroups/search";
$smartgroup_refresh = "/api/mdm/smartgroups";

#Load the shared device config
Try{
    $SharedConfigFile = [IO.File]::ReadAllText("$current_path\shared.config");
    $SharedConfig = ConvertFrom-JSON -InputObject $SharedConfigFile;
} Catch {
    return;
}

If($SharedConfig.SharedConfig){
    #CheckforOGIds
    $LogoffGroupId = $SharedConfig.SharedConfig.LogoffGroupId;
    $OG_Search = Invoke-AWApiCommand -Endpoint ("$og_search_endpoint`?groupid=$LogoffGroupId" ) -ApiVersion 2;
    If($OG_Search.OrganizationGroups){
        $LogoffGroupIdNum = $OG_Search.OrganizationGroups[0].Id;
    }
        
    $LogonGroupId = $SharedConfig.SharedConfig.LogonGroupId;
    $OG_Search = Invoke-AWApiCommand -Endpoint ("$og_search_endpoint`?groupid=$LogonGroupId" ) -ApiVersion 2;
    If($OG_Search.OrganizationGroups){
        $LogonGroupIdNum = $OG_Search.OrganizationGroups[0].Id;
    }
} Else {
    return;
}

#Doublecheck the login / logout numbers
If(!$LogonGroupIdNum -or !$LogoffGroupIdNum){
    return
}

$device_info = Invoke-AWApiCommand -Endpoint $device_endpoint
If($device_info){
   $OrganizationGroupName = $device_info.LocationGroupName;
   $OGIDSearch = Invoke-AWApiCommand -Endpoint ("$og_search_endpoint`?name=$OrganizationGroupName" ) -ApiVersion 2;
   If($OGIDSearch.OrganizationGroups){
      $CurrentOrganizationGroupId = $OGIDSearch.OrganizationGroups[0].Id;
   } Else{
      return;
   }

   #Get current logged in user
   $StagingUsername = $SharedConfig.SharedConfig.StagingUser;  
   If($device_info.Ownership -eq "S" -and $CurrentOrganizationGroupId -eq $LogonGroupIdNum){           
       $user_search = Invoke-AWApiCommand -Endpoint "$user_search_endpoint`?username=$StagingUsername"
       If($user_search){
            $SharedUserId = $user_search.Users[0].Id.Value   
            If($SharedUserId){
                $change_users = Invoke-AWApiCommand -Endpoint "$change_user_endpoint/$SharedUserId" -Method PATCH;
                if($change_users){
                    $OG_Switch = Invoke-AWApiCommand -Method Put -Endpoint ($change_og_endpoint + "$LogoffGroupIdNum") 
                }
            }
            return;
       }
   } 
}