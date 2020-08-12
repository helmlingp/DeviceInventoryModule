#############################################
# File: Uninstall.ps1
# Author: Chase Bradley
# Modified by: Phil Helmling 29 Oct 2019, allow uninstall of single module
#############################################

#Test to see if we are running from the script or if we are running from the ISE
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\ProgramData\Airwatch\";
} 

if(Test-Path "$current_path\setup.manifest"){
    $setup_manifest_file = [IO.File]::ReadAllText($current_path + "\setup.manifest");
    $setup_manifest = ConvertFrom-Json -InputObject $setup_manifest_file;
    $UNINSTALL_FILES = $true;
}

$TestInstall = $false

$InstallPath = "HKLM:\Software\AirWatch\ProductProvisioning";
$ModuleRegPath = $InstallPath;
$ProfileCache = "C:\Program Files (x86)\AirWatch\AgentUI\Cache\Profiles";
$TaskPath = "\AirWatch MDM\";
$shared_path_property = Get-ItemProperty -Path $InstallPath -Name "SharedIPath";
$shared_path = $shared_path_property.SharedIPath
    If($TestInstall){
        Write-Host "Shared Path: $shared_path";
    }

function Get-ItemPropertyValueSafe{
    Param([string]$Path, [string]$Name,$DefaultVal)
    $ReturnVal = $DefaultVal
    If(Test-Path $Path){
        If(Test-ItemProperty -Path $Path -Name $Name){
            $ReturnVal = Get-ItemPropertyValue -Path $Path -Name $Name;
        }
    }
    return $ReturnVal;
}

function Test-ItemProperty{
    Param([string]$Path, [string]$Name)
    return (Get-Item -Path $Path).GetValue($Name) -ne $null;
}

Function Get-InstallerPath{
    param([string]$Path, $Dictionary)

    If($Path -match "\`$([^\\]*)"){
        $Lookup = $Matches[1];
        If($Dictionary.ContainsKey($Lookup)){
            $Path = $Path.Replace($Matches[0],$Dictionary[$Lookup]);
        }
    }
    return $Path;
}

Function Invoke-UnInstallation{
    Param([object]$MyModule,[bool]$TestInstall=$false,[bool]$Install=$true)

    $ModuleName = $MyModule.Name;
    $ModuleInstallPath = $MyModule.InstallLocation;

    If($TestInstall){
        write-host "Module Name: $ModuleName";
        Write-Host "Module Path: $ModuleInstallPath";
        Write-Host "Module Reg Path: $ModuleRegPath";
    }
    
    $PathInfoString = ""
    $PathInfo = @{};
    $PropertyPaths = $MyModule.PSObject.Properties | where TypeNameOfValue -EQ "System.String";
    ForEach($PPath in $PropertyPaths){
        $PathInfo.Add($PPath.Name, $PPath.Value);
        $PathInfoString += "(" + $PPath.Name + ";" + $PPath.Value + ")";
    }
    If($TestInstall){
        Write-Host "Module details: $PathInfoString";
    }

    ForEach($ManifestItem in $MyModule.Manifest){
        $ManifestAction = $ManifestItem.PSObject.Properties.Name 
        
        If ($ManifestAction -eq "CreateTask"){
            $TaskName = $ManifestItem."$ManifestAction".Name;
            
			If($TestInstall){
				Write-Host "Manifest Task: $TaskName at $TaskPath";
			}

			If($TestInstall){
				Write-Host "Unregister ScheduledTask: $TaskName at $TaskPath";
			}
			Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -WhatIf:$TestInstall

        } ElseIf ($ManifestAction -eq "CreateRegKeys"){
            ForEach($RegKey In $ManifestItem."$ManifestAction".Keys){
                $KeyName = ($RegKey.PSObject.Properties | Select Name).Name;
                $KeyValue = $RegKey."$KeyName";
                If($TestInstall){
                    Write-Host "Manifest Reg Key: $KeyName";
                    Write-Host "Manifest Reg Value: $KeyValue";
                }
                If($KeyName -eq "LogPath"){
                    If($TestInstall){
						Write-Host "Do Not remove LogPath as may be used by other Modules";
                    }
                } Else {
                    Remove-ItemProperty -Path $ModuleRegPath -Name $KeyName -Force -WhatIf:$TestInstall;
                }
            }

        } ElseIf($ManifestAction -eq "CopyFiles" -or $ManifestAction -eq "MoveFiles"){                
            $CopyDestination = $ManifestItem.CopyFiles.Destination;
            $CopyDestination = Get-InstallerPath -Path $CopyDestination -Dictionary $PathInfo
            If($TestInstall){
                Write-Host "CopyDestination: $CopyDestination"
            }
            ####GET RIGHTS BACK FIRST####
            If(Test-Path "$shared_path\accesspolicies.access"){
                $RawData = [IO.File]::ReadAllText("$shared_path\accesspolicies.access");
                $Access = ConvertFrom-Json -InputObject $RawData;

                $DefaultAccessLogic1 = New-Object -TypeName PSCustomObject -Property @{"User"="Administrator";"Rule"= "NOTIN"}
                $DefaultAccessProperties = @{"AccessLogic"=@($DefaultAccessLogic0,$DefaultAccessLogic1)};
                $AccessRules = @($DefaultAccessProperties);
                $Access.AccessRules = @()
                $Access.AccessRules += $AccessRules;

                $AccessJson = ConvertTo-Json -InputObject $Access -Depth 10;
                If($TestInstall){
                    Write-Host $AccessJson
                } Else {
                    Set-Content -Path "$shared_path\accesspolicies.access" -Value $AccessJson
					$TaskName = "Apply_AccessPolicies";
                    If((Get-ScheduledTask | where {$_.TaskName -eq $TaskName -and 
                            $_.TaskPath -eq $TaskPath} | measure).Count -gt 0){
                        Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath;
                    }
                }
            }

            Remove-Item -Path $CopyDestination -Recurse -Force -WhatIf:$TestInstall;
        }
		
		If(Test-ItemProperty $ModuleRegPath "$ModuleName`IVersion"){
            Remove-ItemProperty -Path $ModuleRegPath -Name "$ModuleName`IVersion" -Force -WhatIf:$TestInstall;
            Remove-ItemProperty -Path $ModuleRegPath -Name "$ModuleName`IPath" -Force -WhatIf:$TestInstall;
		}
    }
}

Set-Location -Path $current_path;

Write-Host "*******************************************";
Write-Host "Beginning Uninstall";
Write-Host "";
Write-Host "*******************************************";

If($UNINSTALL_FILES){ 
    ForEach($MyModule in $setup_manifest.Modules | where Name -ne "Shared"){
        #do not uninstall the Shared Module as this is used by many modules
        Write-Host "Uninstalling: $MyModule"
        
        Invoke-UnInstallation $MyModule $TestInstall $true;
    }
    $InstallPathDirs = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -like "*IPath") | Measure;
    If($InstallPathDirs.Count -gt 1){
        #do nothing as other Modules still installed
        Write-Host "Other Modules still installed"
        
     } Else {
         #if only Shared Module left, not needed anymore so uninstall
        $MyModule = $setup_manifest.Modules | where Name -eq "Shared";
        Write-Host "Uninstalling: $MyModule"

		#Remove other Module items listed in setup.manifest
        Invoke-UnInstallation $MyModule;

        #ProductProvisioning Registry SubFolders are left over so remove them
        Remove-Item -Path $ModuleRegPath -Recurse -WhatIf:$TestInstall;
        #Some Modules create a Profile Cache folder so remove it
        If(Test-Path $ProfileCache){
            Remove-Item -Path $ProfileCache -Recurse -Force -WhatIf:$TestInstall;
        }
    }
}
