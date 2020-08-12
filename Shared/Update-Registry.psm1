<#
    File: Update-Registry.ps1
    Author: cbradley@vmware.com
	Modified by Phil Helmling: 27 Nov 2019, optimised and restructured to reduce API calls
#>

#==========================Header=============================#
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Reg";
}

Unblock-File "$Global:shared_path\Helpers.psm1"
$LocalHelpers = Import-Module "$Global:shared_path\Helpers.psm1" -ErrorAction Stop -PassThru -Force;

$shared_path = $Global:shared_path;
#$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$Global:log_path\RegistryModule.log"; 
$securityLogLocation = "$Global:log_path\SecurityAudit.log";

$GlobalModules = @();
$GlobalImporter = @("$shared_path\Utility-Functions.psm1")
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

If(!(Test-Path "$current_path\Audit")){
    New-Item -Path "$current_path" -Name "Audit" -ItemType Directory -Force;
}

$AuditDatabasePath = "$Global:current_path\Audit\Registry.db";

If(!(Test-Path "HKU:")){
    New-PSDrive HKU Registry HKEY_USERS  
}

function ConvertTo-CustomVariableSafeString{
    param([string]$input_string)
    $formatter = $input_string;
    If($formatter -match "^[A-Za-z0-9\``\!\@\#\`$\^\(\)\%\-_\+\=\'\,\.]*$"){
        #string is valid
        return $formatter;
    } else {
        $MappedChars = @{"`""="'";"'"="``";"\\"="`,";"\"="`,";"/"="`.";"::"="`!";":"="`!";";"="`%"}
        ForEach($Mapped in $MappedChars.Keys){
            $formatter = $formatter.Replace($Mapped, $MappedChars[$Mapped]);
        }
        If($formatter -match "[A-Za-z0-9\``\!\@\#\`$\^\(\)\%\-_\+\=\'\,\.]*"){
            return $formatter;
        } else {
            $longFormatter = "";
            foreach($char in $formatter){
                if($char -notmatch "[A-Za-z0-9\``\!\@\#\`$\^\(\)\%\-\_\+\=\'\,\.]"){
                    $longFormatter += "`%";
                } else {
                    $longFormatter += $char;
                }
            }
            return $longFormatter
        }
    }
}

function Remove-ProfileFromDB{
    param([string]$Profile)
    $Audit = Open-AuditDatabase($AuditDatabasePath);
    If($Audit.RemoveProfile($Profile)){
        $Audit.Commit();
    }

    $Audit.Close();
}

function Set-RegistryKeyValues{
    param([string]$Profile,[string]$Path, $KeyValues,[bool]$IsDebug,[switch]$CustomVariableFormatted,[switch]$DisableAudit)
    
    If(!($DisableAudit.IsPresent)){
        $Audit = Open-AuditDatabase($AuditDatabasePath);
        If(!($Audit.GetProfile($Profile))){
            $Audit.AddProfile($Profile);
        }
    }

    #Convert Hashtable into an object for easier management
    $KeyValueObjects = @();
    If($KeyValues.GetType().Name -eq "Hashtable"){
        $KeyValues.Keys | % {$KeyValueObjects += New-Object PSCustomObject -Property @{"ValueName"=$_;"Value"=$KeyValues[$_]}};
    } Else {
        $KeyValueObjects += $KeyValues;
    }

    If($Path){
        $RegPath = $Path;
        $DefaultPath = (Get-RegKeyFormat -Path $RegPath).FullPath;
    }
    $RegNewPaths = @();
    $RegValueResults = @();
    ForEach($KeyValueObj in $KeyValueObjects){
            $KeyValueObj | Add-Member -MemberType NoteProperty -Name "Status" -Value "";
            $RegPath = $DefaultPath;
            If($KeyValueObj.Path){
                $RegPath = (Get-RegKeyFormat -Path $KeyValueObj.Path).FullPath;
            } 

            If(!(Test-Path $RegPath)){
                 $RegValueResults += New-RegistryKey -Path $RegPath;
            }
            If(($KeyValueObj.PSObject.Properties | where Name -eq "Path" | measure).Count -eq 0){
                $KeyValueObj | Add-Member -MemberType NoteProperty -Name "Path" -Value $RegPath;
            }

            #Determine Type
            $RegValueName = $KeyValueObj.ValueName;
            $RegValue = $KeyValueObj.Value;
            $RegType = "String";
            If($RegValue.Type){
                 $RegType = $RegValue.Type;  
            } Else{   
                 $typeInformation = Test-RegValueType -object $RegValue;
                 $RegValue = $typeInformation["Value"];
                 $RegType = $typeInformation["Type"];
                 If($isDebug){ Write-Log2 -Path $logLocation -Message "Determed value as $RegType."; }
                 $KeyValueObj | Add-Member -MemberType NoteProperty -Name "Type" -Value $RegType;
            }

            If($RegType -eq "String" -and $CustomVariableFormatted.IsPresent){
                $RegValue = ConvertTo-CustomVariableSafeString $RegValue;
            }
            $KeyValueObj.Value = $RegValue;

            If(Test-Path $RegPath){
                $OldValue = Get-ItemPropertyValueSafe -Path $RegPath -Name $RegValueName -DefaultVal $null;
                $keyValueObj | Add-Member -MemberType NoteProperty -Name "OldValue" -Value $OldValue;
            }
                              
            Try{
                If($OldValue -ne $RegValue -or ($OldValue -eq $null)){
                    $RegSet = New-ItemProperty -path $RegPath -name $RegValueName -value $RegValue -PropertyType $RegType -Force;
                    If($OldValue){
                        $KeyValueObj.Status = "Modified";   
                    } Else{
                        $KeyValueObj.Status = "New";
                    }
                } Else{
                    $KeyValueObj.Status = "Managed";
                }
            } Catch {
                $errorMessage = $_.ExceptionMessage;
                $KeyValueObj.Status = "Error";
                Write-Log2 -Path $logLocation -Message "An error has occured writing to $path. " -Level Error;
            }
            $RegValueResults += $KeyValueObj;
        }
        
        If(!($DisableAudit.IsPresent)){
            $Updated = $Audit.SetEntries($Profile, $RegValueResults, @("Path","ValueName"), @("Value"));
            If($Updated.Updated){
                $Audit.Commit();
            }
            $Results = $Updated;
            $Audit.Close();
        } Else {
            $Results = $RegValueResults;
        }
        return $Results;
}   

function Test-RegValueType{
    Param($object)
    $result = @{"Type"="String";"Value"=$object}
    if("$object" -ne ""){
        if(($object | measure).Count -eq 1){ 
            if($object | Test-IsInt){
                $result["Type"] = "Dword";            
            } elseif($object.ToString().ToLower().StartsWith("dword:")){
                $result["Type"] = "Dword"
                $result["Value"] = $object.ToString().Replace("dword:","");
            }
        } else{
            if($object["Type"] -and $object["Value"]){
                $result["Type"] = $object["Type"];
                $result["Value"] = $object["Value"];
            }
        }
    }
    return $result;
}

function Get-RegKeyFormat{
    Param([string]$Path, [string]$User)

    $RegKeyResults = New-Object PSCustomObject -Property @{"Drive"="";"FullPath"="";"Key"=""};
   
    $RegKeyMatch = @{"HKEY_LOCAL_MACHINE"="HKLM:";"HKEY_CURRENT_USER"="HKCU:";"HKEY_USER"="HKU:"}

    $FullPath = $Path;
    If($FullPath -match "(HK[A-Za-z]{1,3}:|(HKEY_[^\\]*))(\\.*)+"){
        $RegPath = $Matches[1];
        If($Matches.Count -eq 4){
            $RegPath = $RegKeyMatch[$Matches[2]];
            $FullPath = $FullPath.Replace($Matches[2],$RegPath)
        }
        $RegKeyResults.Drive = $RegPath;
    } Else{
        Write-Log2 -Path $logLocation -Message "Error, registry key path did not match required format.  (Examples: 'HKLM:\Path\To\Key' or 'HKEY_Local_Machine\Path\To\Key)" -Level Error;
        return $false;
    } 

     If(!(Test-Path "HKU:")){
        New-PSDrive HKU Registry HKEY_USERS  
    }

    #User logic
    if($RegPath -ne "HKLM:"){
        if($RegPath -eq "HKCU:"){
            $UserSID = Get-UserSIDLookup("(current_user)");
            $FullPath = $FullPath.Replace("HKCU:\","HKU:\$UserSID\");
        } elseif($RegPath -eq "HKU:"){
            if($User){
                $UserSID = Get-UserSIDLookup($User);
                $FullPath = $FullPath.Replace("HKU:\","HKU:\$UserSID\");
            } elseif($FullPath -match "HKU:\\%([^%\\]*)%\\"){
                $User = $Matches[1];
                $UserSID = Get-UserSIDLookup($User);
                $FullPath.Replace("%$User%", $UserSID);
            } elseif($FullPath -match "HCU:\\(SID-[0-9\-]*)\\"){
                $UserSID = $Matches[1];
            }
        } else{
            Write-Log2 -Path $logLocation -Message "An invalid registry path was specified. " -Level Error
            return;
        }
        if($sid.BeginsWith("Error:")){
            Write-Log2 -Path $logLocation -Message "An error has occured: $UserSID" -Level Error
            return;
        }
        $RegPath = "HKU:";
    }
        
    #Clean up full path to remove trailing slash
    if($FullPath.EndsWith("\")){
        $FullPath = $FullPath.Substring(0, $FullPath.Length - 1);
    }

    $RegKeyResults.FullPath = $FullPath;
    $RegKeyResults.Key = $FullPath.Replace("$RegPath\", "");

    return $RegKeyResults;
}

function New-RegistryKey {
    param([string]$Path, [bool]$IsDebug=$false)
    
    $Path = (Get-RegKeyFormat -Path $Path).FullPath;
    $PathTest = $Path;
    $NewPaths = @();
    While(!(Test-Path $PathTest)){
        $NewPaths += New-Object -TypeName PSCustomObject -Property @{"Path"=$PathTest;"ValueName"="";"Value"="";"Status"="New";"OldValue"="";"Type"=""}
        If($PathTest -match "(.*)\\[^\\]*$"){
            $PathTest = $Matches[1];
        } Else{
            return @();
        }
    }
   
    Try{
        $Result = New-Item -Path $Path -Force;
    } Catch{
        return @();
    }
    
    return $NewPaths;
}

add-type -Language CSharp @'
    public class Helpers {
        public static bool IsInt(object o) {
            int o2;
            if(int.TryParse(o.ToString(), out o2)){
                return true;
            }
            return o is short  || o is int  || o is long || o is uint;
        }
    }       
'@


filter Test-IsInt {
    [Helpers]::isInt($_)
}


Export-ModuleMember -Function ConvertTo-CustomVariableSafeString, Remove-ProfileFromDB, Set-RegistryKeyValues, Test-RegValueType, Get-RegKeyFormat, New-RegistryKey