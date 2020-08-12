<#
    File: SmarterGroupsLogic.psm1
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
$GlobalImporter = @("$shared_path\Database-Management.psm1", "$shared_path\Update-Registry.psm1", 
                        "$shared_path\AirWatchAPI.psm1", "$shared_path\Utility-Functions.psm1");

foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$log_path\SmarterGroupsLogic.log"; 


$LocalCacheDBPath = "$current_path\Profiles\InstallList.db";

Function Remove-CustomSettingsProfile{
    param($ProfileId,$RegPath,[switch]$DeleteKey)
    
    $RegPaths = @() + $RegPath;
    #Get Custom XML profile path to store the custom variables
    If($ProfileId -match "[^\\\.]*(?:.xml|$)"){
        $airwatchInstallDir = Get-ItemPropertyValueSafe -Path "HKLM:\Software\AIRWATCH" -Name "INSTALLDIR" -DefaultVal "C:\Program Files (x86)\AirWatch";
        $xmlPath = $airwatchInstallDir + "\AgentUI\Cache\Profiles\$ProfileId";
        If(!($xmlPath.Contains(".xml"))){
            $xmlPath += ".xml";
        }
    } Else {
        return $false;
    }
    

    If($DeleteKey.IsPresent){
        ForEach($RegKey in $RegPaths){
            If(Test-Path $RegKey){
                Remove-Item -Path $RegKey -Force;
            }
        }
    } Else{

    
    }

    If(Test-Path $xmlPath){
        Remove-Item -Path $xmlPath -Force;
    }

    Remove-ProfileFromDB -Profile $ProfileId;
}


function New-CustomVariableObj{
    param([string]$Path, [string]$ValueName, $Value, [string]$Type="", [string]$Alias)

    $PathFormatter = (Get-RegKeyFormat $Path);
    $Path = $PathFormatter.FullPath;
    $KeyPath = $PathFormatter.Key;
    
    
    $CustomVariableParam = @{"Path"=$Path;"KeyPath"=$KeyPath;"ValueName"=$ValueName;"Value"=$Value;"Alias"=$Alias};
    If($Type){ $CustomVariableParam.Add("Type",$Type); }
    $CustomVariableObj = New-Object -TypeName PSCustomObject -Property $CustomVariableParam;

    return $CustomVariableObj;
}

function Remove-CvDeletedEntries{
    param([string]$RegKeyPath, $AliasObjects)
    #Purge the registry
    
    $CurrentRegKeySet = @();
    If(Test-Path $RegKeyPath){
        $CurrentRegKeySet = (Get-Item -Path $RegKeyPath).Property;
    } 

    $temp = $CurrentRegKeySet | % {if($_ -notin ($AliasObjects | Select ValueName).ValueName){return $_}}
    foreach($tempreg in $temp){
        try{
            $i = Remove-ItemProperty -Path $RegKeyPath -Name $tempreg -Force;
        } catch{
            $ErrorMessage = $_.Exception.Message;
            Write-Log2 -Path $logLocation -Message $ErrorMessage
        }
    }
}

$XMLTemplateIF = @'
<xml version="1.0">
<wap-provisioningdoc name="System Info /V_1">
	<characteristic type="com.windowspc.getregistryinfo.managed">
		<reg_value value_name="valuename" key_name="keyname" custom_attribute_name="caname"/>
	</characteristic>
	
</wap-provisioningdoc>
</xml>
'@

function Set-CustomVariables{
    param([string]$ProfileName, [string]$KeyPath, $aliasMap=@{}, $AliasObjects=@(), [switch]$RemoveDeletedEntries, [switch]$DisableAudit, [switch]$Rebuild)

    $RegKeyPath = "HKLM:\$KeyPath"
    #Validate RegKeys path
    If($KeyPath -like "*:\*"){
        $KeyPathReset = Get-RegKeyFormat $KeyPath;
        $RegKeyPath = $KeyPathReset.FullPath;
        $KeyPath = $KeyPathReset.Key;
    }
   

    #Get Custom XML profile path to store the custom variables
    If($ProfileName -match "[^\\\.]*(?:.xml|$)"){
        $airwatchInstallDir = Get-ItemPropertyValueSafe -Path "HKLM:\Software\AIRWATCH" -Name "INSTALLDIR" -DefaultVal "C:\Program Files (x86)\AirWatch";
        $xmlPath = $airwatchInstallDir + "\AgentUI\Cache\Profiles\$ProfileName";
        If(!(Test-Path "$airwatchInstallDir\AgentUI\Cache\Profiles")){
            New-Item -Path "$airwatchInstallDir\AgentUI\Cache\Profiles" -ItemType Directory;
        }
        If(!($xmlPath.Contains(".xml"))){
            $xmlPath += ".xml";
        }
    }

    $FinalResults = @();
    #Helpers to ensure that we can support both arrays and hash tables 
    If($AliasObjects.Count -eq 0 -and $aliasMap.Count -gt 0){
        #Hack to turn the alias map dictonary into an object
        $aliasMap.Keys | % {$AliasObjects += New-Object -TypeName PSCustomObject -Property @{"ValueName"=$aliasMap[$_];"Alias"=$_;"KeyPath"=$keyPath}};
    } Else{
        #Validate that we have regkey values before commiting to the registry
        $AliasObjects | where { (!$_.KeyPath) } | % {$_ | Add-Member -MemberType NoteProperty -Name "KeyPath" -Value "$keyPath"};
        If($AliasObjects | Where {$_.Value}){
            $RegKeys = $AliasObjects | Select ValueName, Value, @{N='Path'; E={ If($_.Path) { $_.Path } Else { "$RegKeyPath" } }} | Where {$_.Value};;
            $FinalResults = Set-RegistryKeyValues -Profile "CustomSettings" -KeyValues $RegKeys -CustomVariableFormatted -DisableAudit:($DisableAudit.IsPresent)
        }

        #Remove deleted entries from the regkey
        If($RemoveDeletedEntries.IsPresent){
            Remove-CvDeletedEntries -RegKeyPath $RegKeyPath -AliasObjects $AliasObjects
        }
    }

    If($Rebuild.IsPresent -and (Test-Path $xmlPath)){
        Remove-Item $xmlPath -Force;    
    }

    If($AliasObjects) { 
        $RegKeyValidate = $AliasObjects | Select *, @{N="Key";E={$_.Alias + "=" + $_.KeyPath + "!" + $_.ValueName}}   
        If(Test-Path $xmlPath){
            [xml]$XmlDocument = Get-Content -Path $xmlPath
            If($XmlDocument.HasChildNodes){
                #Get XML nodes with unique key
                $xmlItem = $XmlDocument.xml.'wap-provisioningdoc';
                $XmlItemNodes = $xmlItem.characteristic | select @{N='Xml';E={$_}}, @{N='Key';E={$_.reg_value.custom_attribute_name + "=" + $_.reg_value.key_name + "!" + $_.reg_value.value_name}}
                $XmlNodes = ($xmlItem.characteristic | select reg_value).reg_value | select key_name, custom_attribute_name, value_name, @{N='Key';
                        E={$_.custom_attribute_name + "=" + $_.key_name + "!" + $_.value_name}};

                #New Value and Remove Value Calculator
                $NewValues = $RegKeyValidate | where {$_.Key -notin ($XMLNodes | Select Key).Key};
                $RemoveValues = $XmlItemNode | where {$_.Key -notin ($RegKeyValidate | Select Key).Key -and $_.Key -notlike "*caname*"};

                #XML objects are difficult to work with but if you reference the object you can remove it yourself
                If(($RemoveValues | Measure).Count -gt 0){
                    $RemoveValues | % {$xmlItem.RemoveChild($_.xml)};
                    $XmlDocument.Save($xmlPath);
                }            
            } Else{
                Remove-Item $xmlPath -Force;
                $NewValues = $RegKeyValidate;
            }
        } Else {
            $NewValues = $RegKeyValidate
        }
    }
    

    
    If(($NewValues | Measure).Count -gt 0){
        If(Test-Path $xmlPath){
            [xml]$XmlDocument = Get-Content -Path $xmlPath 
        } else {
            [xml]$XmlDocument = $XMLTemplateIF;
        }
        $xmlItem = $XmlDocument.xml.'wap-provisioningdoc';
              
        ForEach($NewValue in $NewValues){
                $x = $xmlItem.ChildNodes[0].Clone();
                $x.reg_value.value_name = $NewValue.ValueName.ToString();
                $x.reg_value.key_name = $NewValue.KeyPath.ToString();
                $x.reg_value.custom_attribute_name = $NewValue.Alias.ToString() ;
             
                $xmlItem.AppendChild($x);
        }
        $xmlPath_Path = $xmlPath.Substring(0,$xmlPath.LastIndexOf("\"));
        if(!(Test-Path $xmlPath_Path)){
            New-Item -Path $xmlPath_Path -Force;
        }
            
        $XmlDocument.Save($xmlPath);
    }
    return $FinalResults;
}

Export-ModuleMember -Function Set-CustomVariables, New-CustomVariableObj, Remove-CustomSettingsProfile