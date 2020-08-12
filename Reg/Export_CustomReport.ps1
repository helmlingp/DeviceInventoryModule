<#
    File: Export_CustomReport.ps1
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
$GlobalImporter = @(, 
        "$shared_path\AirWatchAPI.psm1","$shared_path\Utility-Functions.psm1")
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

$device_endpoint = "/api/mdm/devices/{DeviceId}/";
$device_search_endpoint = "/api/mdm/devices/{DeviceId}/";
$change_user_endpoint = "/api/mdm/devices/{DeviceId}/enrollmentuser/";
$user_search_endpoint = "/api/system/users/search";
$user_details_endpoint = "/api/system/users/";
$og_search_endpoint = "/api/system/groups/search";
$change_og_endpoint = "/api/mdm/devices/{DeviceId}/commands/changeorganizationgroup/";
$smartgroup_search = "/api/mdm/smartgroups/search";
$smartgroup_refresh = "/api/mdm/smartgroups";


$deviceSearch = "api/mdm/devices/search"
$deviceNotesEndpoint = "api/mdm/devices/{DeviceId}/notes"

#hostname, past vulnerabilities (past 30 days), times/dates and infection name/infected file name
$devices = Invoke-AWApiCommand -Endpoint $deviceSearch -ApiVersion 2;

$DeviceNoteList = @();
$DeviceIds = (($devices.Devices | Select Id).Id | Select Value).Value;
ForEach($deviceId in $DeviceIds){
    $DeviceNotes = Invoke-AWApiCommand -Endpoint $deviceNotesEndpoint.Replace("{DeviceId}",$deviceId) -ApiVersion 2;
    ForEach($Note in $DeviceNotes.DeviceNotes){
        If($Note.Note){
            $NoteConvert = $Note.Note
            If($NoteConvert.Contains('"Hostname",')){
                $NoteConvert = ConvertFrom-Csv $NoteConvert
                $DeviceNoteList += @($NoteConvert);
            }
        }
    }  
}

$timestamp = Get-Date -format yyyyMMdd;
$ExportPathCount = (Get-ChildItem -Path $current_path -Force -Filter "export$timestamp*.csv" | measure).Count; 
$ExportFullPath = $current_path + "\export$timestamp" + "_" + "$ExportPathCount.csv";

$DeviceNoteList | Export-CSV -Path $ExportFullPath -NoTypeInformation

