<#
    File: Helpers.psm1
    Author: cbradley@vmware.com
	Modified by Phil Helmling: 27 Nov 2019, provide paths as Global variables
#>

$InstallPath = "HKLM:\Software\AIRWATCH\ProductProvisioning";

$shared_path = "C:\Temp\Shared"
If(Test-Path $InstallPath){
    $getShared_path = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -eq "SharedPath") | Measure;
    If($getShared_path.Count -gt 0){
        $shared_path = Get-ItemPropertyValue -Path $InstallPath -Name "SharedPath";       
    }
	
	$getlog_path = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -eq "LogPath") | Measure;
	If($getlog_path.Count -gt 0){
        $log_path = Get-ItemPropertyValue -Path $InstallPath -Name "LogPath";       
    }
}

#Sets the global Registry Install path
#Set-Variable -Name "InstallPath" -Value $InstallPath -Scope "Global"
$Global:InstallPath = $InstallPath;

#Sets the global Shared Path location
#Set-Variable -Name "shared_path" -Value $shared_path -Scope "Global"
$Global:shared_path = $shared_path;

#Sets the global Log Path location
#Set-Variable -Name "log_path" -Value $log_path -Scope "Global"
$Global:log_path = $log_path;
