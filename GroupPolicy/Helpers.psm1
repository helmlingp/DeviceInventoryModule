<#
    File: Helpers.psm1
    Author: cbradley@vmware.com
#>

$InstallPath = "HKLM:\Software\AIRWATCH\ProductProvisioning";

$shared_path = "C:\Temp\Shared"
If(Test-Path $InstallPath){
    $getShared_path = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -eq "SharedPath") | Measure;
    If($getShared_path.Count -gt 0){
        $shared_path = Get-ItemPropertyValue -Path $InstallPath -Name "SharedPath";       
    }
}

#Sets the global Registry Install path
$Global:InstallPath = $InstallPath;

#Sets the global Shared Path location
$Global:shared_path = $shared_path;

#$InstallPathDirs = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -like "*IPath" | Select Value).Value

