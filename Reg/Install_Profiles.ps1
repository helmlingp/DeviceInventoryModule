<#
    File: Import_CustomSettings.ps1
    Author: cbradley@vmware.com
#>
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Reg";
}

Unblock-File "$current_path\Helpers.psm1"
$LocalHelpers = Import-Module "$current_path\Helpers.psm1" -ErrorAction Stop -PassThru -Force;

$shared_path = $Global:shared_path;

$GlobalModules = @();
$GlobalImporter = @("$current_path\SmarterGroupsLogic.psm1", "$current_path\ProfileManagement.psm1",
    "$shared_path\Utility-Functions.psm1")
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}     

$GPPath = Get-ItemPropertyValueSafe -Path $InstallPath -Name "ImportGroupPolicy-Path" -DefaultVal "C:\Temp\GroupPolicy";

$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$log_path\Profiles.log"; 

<#================Module Body====================#>
$raw_profile_files = @();
$raw_profiles = Get-ChildItem -Path "$current_path\Queue" -Filter "*.profile" -Force
if($raw_profiles){
    $raw_profile_files += $raw_profiles;
}
$unattended_profiles = Get-ChildItem -Path "C:\Temp" -Filter "*.profile" -Force
If(!$unattended){
    $raw_profile_files += $unattended_profiles;
}

$DefaultFunctionality = @("SmarterGroups";"CustomAttributes";"PerformanceCounter");
$Extenions = @{"SmarterGroups"="map";"CustomAttributes"="settings";"GroupPolicy"="txt";"PSProfile"="ps1x";"PerformanceCounter"="counters"};
$TaskPath = "\AirWatch MDM\";
$TaskList = @{"SmarterGroups"="Install_SmarterGroups";"CustomAttributes"="Install_CustomSettings";"GroupPolicy"="Import_GroupPolicy";"PerformanceCounter"="Install_PollCounter"};

$AWProfileList = "";
ForEach($raw_profile in $raw_profile_files){
    $Data = [IO.File]::ReadAllText($raw_profile.FullName);
    $RawName = $raw_profile.BaseName;
    If($RawName -match "([^\-]*)\-([0-9]{1,10}|(NP[0-9]{1,10}))"){
        $TemplateType = $Matches[1];
        $Name = $Matches[2];
        #New profile detected - get profileId
        If($Matches.Count -eq 4){
            If(!($AWProfileList)){
                $AWProfileList = Get-AssignedAirWatchProfiles;
                If($AWProfileList){
                    $CurrentProfile = $AWProfileList | where {$_.Description -eq $Matches[3]};
                    If($CurrentProfile){
                        $Name = $CurrentProfile.Id;
                    }
                }
            }
        }
        $Extension = $Extenions[$TemplateType];
        If ($TemplateType -in $DefaultFunctionality){
                $DecodedData = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Data));
                $EncryptedData = ConvertTo-EncryptedFile $DecodedData;
                Set-Content -Path "$current_path\Profiles\$Name.$Extension" -Value $EncryptedData -Force;
                Remove-Item -Path $raw_profile.FullName;     
        } ElseIf($TemplateType -eq "GroupPolicy"){
                $DecodedData = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Data));
                $EncryptedData = ConvertTo-EncryptedFile $DecodedData;
                Set-Content -Path "$GPPath\Queue\$Name.$Extension" -Value $EncryptedData -Force;
                Remove-Item -Path $raw_profile.FullName;
        } ElseIf($TemplateType -eq "PSProfile"){
                $DecodedData = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Data));
                If($DecodedData -match "(?s)\#START_INSTALL_CMD`n(.*)\#END_INSTALL_CMD`n\#START_UNINSTALL_CMD`n(.*)\#END_UNINSTALL_CMD"){
                    $InstallPS = $Matches[1];
                    $UninstallPS = $Matches[2];
                    Try{
                        $Results = (iex $InstallPS)
                        $EncryptedData = ConvertTo-EncryptedFile $UninstallPS;
                        Set-Content -Path "$current_path\Profiles\$Name.$Extension" -Value $EncryptedData -Force;
                    } Catch{

                    }
                }
                Remove-Item -Path $raw_profile.FullName;
                continue;
        } Else {
            continue;
        }
        Start-ScheduledTask -TaskName $TaskList[$TemplateType] -TaskPath $TaskPath;
    }
}

