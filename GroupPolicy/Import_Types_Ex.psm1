<#
    File: Import_Types_Ex.psm1
    Author: cbradley@vmware.com
#>

#==========================Header=============================#
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\GroupPolicy";
}

Unblock-File "$current_path\Helpers.psm1"
$LocalHelpers = Import-Module "$current_path\Helpers.psm1" -ErrorAction Stop -PassThru -Force;

$reg_path = ($current_path | Split-Path -Parent) + "\Reg";

$shared_path = $Global:shared_path;

$GlobalModules = @();
$GlobalImporter = @("$shared_path\Security-Functions.psm1","$reg_path\ProfileManagement.psm1","$reg_path\CustomSettingsLib.psm1",
            "$shared_path\Database-Management.psm1",
            "$shared_path\AirWatchAPI.psm1","$shared_path\Utility-Functions.psm1")
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = $log_path + "\GroupPolicyLogs.log";        

Unblock-File "$current_path\LGPO.exe";    

#These are the designated folders to process the .CSV files
$errorP = "$current_path\Audit";
$AuditDatabase = "$current_path\Audit\AuditDB_MV.db";

#Usermap to store and maintain SID list so we don't have to look them up
$UserMap = @{};


<#
==============================================================
Module Body
==============================================================
#>

function Invoke-LGPO{
    param([string]$LGPOArgs)
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$current_path\LGPO.exe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true;
    $pinfo.Arguments = $LGPOArgs;
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit(10000)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    if($p.ExitCode -eq 0){   
        $returnVar = $stdout;
        return $returnVar;
    } else {
        return $stderr;
    }
}

Function Get-RegistryKey{
    param([object]$Entry)
    $RegKey = "";
    If($Entry.Context){
        $Context = $Entry.Context;
        $Key = $Entry.Key;
        $ValueName = $Entry.ValueName;
    
        If($Context -eq "Computer"){
            $RegKey = "HKLM:\$Key!$ValueName";
        } ElseIf ($Context -eq "User"){
            $RegKey = "HCU:\$Key!$ValueName";
        } ElseIf ($Context -match "User\:(.*)"){
            if($UserMap.ContainsKey($Matches[1])){
                $SID = $UserMap[$Matches[1]];
            } else{
                $SID = Get-UserSIDLookup -UsernameLookup $Matches[1];
                $UserMap.Add($Matches[1], $SID);
            } 
            $RegKey = "HKU:\$SID\$Key!$ValueName";
        } 
    }
    return $RegKey;
}


function ConvertFrom-LGPOResults{
    param([string]$LGPOContents)
    
    $Entries = @();
    $Lines = $LGPOContents -split "`r`n`r`n";
    $i = 0;
    ForEach($Line in $Lines){
        If($Line -and $Line -notlike ";*"){
            If($Line -match "(Computer|User\:[^\r\n]*|User)\r\n([^\r\n]*)\r\n([^\r\n]*)\r\n([^:]*)(?:\:(.*)|$)"){
                $EntryParse = $Line -split "`r`n";
                if($EntryParse.Length -eq 4){
                    $Entry = $EntryParse[3].Split(":");
                    $Context = $EntryParse[0];
                    $UID = "$Context`::" + $EntryParse[1] + "!" + $EntryParse[2]
                    #$HashedUID = Get-Hash $UID
                    $Properties = @{"UID"=$UID;"Context"=$EntryParse[0];"Key"=$EntryParse[1];
                     "ValueName"=$EntryParse[2];"Type"=("REG_" + $Entry[0]);"Value"=$Entry[1]}
                }
                #Make sure that the Context Exists in the database  
                $Entry = New-Object -TypeName PSCustomObject -Property $Properties;
                $RegKey = Get-RegistryKey -Entry $Entry;
                $Entries += ($Entry | Select *,@{N='RegPath';E={$RegKey}});
            } ElseIf ($Line -match "([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)$"){
                $LGPOLineMatches = $Matches;
                If($LGPOLineMatches[1] -like "Computer Configuration*"){
                    $Context = "Computer"
                } Else {
                    $Context = "User";
                    if($LGPOLineMatches[1] -match ".*user\s(.*)$"){
                        $Context += ":" + $Matches[1];
                    }
                }
                $UID = "$Context`::" + $LGPOLineMatches[2] + "!" +  $LGPOLineMatches[3];
                #$HashedUID = Get-Hash $UID
                $Properties = @{"UID"=$UID;"Context"=$Context;"Key"=$LGPOLineMatches[2];
                    "ValueName"=$LGPOLineMatches[3];"Type"=$LGPOLineMatches[4];"Value"=$LGPOLineMatches[5]}
                $Entry = New-Object -TypeName PSCustomObject -Property $Properties;
                $RegKey = Get-RegistryKey -Entry $Entry;
                $Entries += ($Entry | Select *,@{N='RegPath';E={$RegKey}});
            }
            
        }
    }
    return $Entries;
}


<#
Function: Set-FileMetaData
Author  : cbradley@vmware.com
Description : Lists permissions of an object
Input Params: N/A, Output: String
Example: Set-FileMetaData
        logs permissions in secuirtyAudit.log 
#>
function Get-AliasMap{
    param(
        [string]$FormatedFileName,
        [string]$FormatedRegistryLocation,
        $KeyValues
    )
    $AliasMap = @{};
    
    foreach($KVKey in $KeyValues.Keys){
        $AliasMap.Add("GPO.$FormatedFileName.$KVKey",$KVKey)
    }

    If(!(Test-Path $FormatedRegistryLocation)){
        $nrk = New-RegistryKey -source $FormatedFileName -path $FormatedRegistryLocation;       
    }
    $nrkv = Set-RegistryKeyValue -source $FormatedFileName -key $FormatedRegistryLocation -keyvalues $KeyValues;
    return $AliasMap;
}

<#
Function: Start-RecordAudit
Author  : cbradley@vmware.com
Description : Fixes errors and any outside changes
Input Params: N/A, Output: String
Example: Start-ReconcileGPOs
        logs permissions in secuirtyAudit.log 
#>
Function Start-RecordAudit{
    param([array]$CurrentValues)
    
    $Audit = Open-AuditDatabase -Path $AuditDatabase

    $GPOPath = "HKLM:\Software\AirWatch\GroupPolicy\Audit";
    $AliasPath = "Software\AirWatch\GroupPolicy\Audit"

    If(!(Test-Path "HKU:")){
        New-PSDrive HKU Registry HKEY_USERS  
    }

    $GPOPrefix = "GPOAudit.";
    $FileNameCount = @{};
    $RegistryKeys = @();
    $GPOReport = @{};
    $GPOReportAlias = @{};
    ForEach($Entry in $CurrentValues){
        $AuditEntries =  $Audit.GetEntries("","UID",$Entry.UID);
        If($AuditEntries){
            ForEach($ProfileObj in $AuditEntries.Keys){
                $ProfileId = $ProfileObj;
                If(!$FileNameCount.ContainsKey($ProfileId)){
                    $FileNameCount.Add($ProfileId, 0);
                }
                ForEach($AuditEntry in $AuditEntries[$ProfileId]){
                    #Get Audit information              
                    $AuditRegKeyName = "Profile $ProfileId." + $FileNameCount[$ProfileId]; 
                    $AuditValue = $AuditEntry.Context + "@" + $AuditEntry.ValueName + " = " + $AuditEntry.Value;
                    #Fix value for compatability
                    $AuditValue = $AuditValue;

                    $GPOAlias = "$GPOPrefix$AuditRegKeyName"
                    $GPOReport.Add($AuditRegKeyName, $AuditValue);
                    $GPOReportAlias.Add($GPOAlias, $AuditRegKeyName);

                    #Get Reg Key for protection
                    $RegKey = Get-RegistryKey $AuditEntry;
                    If($RegKey){
                       $RegistryKeys += $RegKey;
                    }
                    $FileNameCount[$ProfileId]++;
                }       
            }
        } else {
            #Get Audit information 
            if(!($FileNameCount.ContainsKey("Unmanaged"))){
                $FileNameCount.Add("Unmanaged",0);
            }             
            $AuditRegKeyName = "Unmanaged." + $FileNameCount["Unmanaged"]; 
            $AuditValue = $Entry.Context + "@" + $Entry.ValueName + " = " + $Entry.Value;
            #Fix value for compatability
            $AuditValue = $AuditValue;

            $GPOAlias = "$GPOPrefix$AuditRegKeyName"
            $GPOReport.Add($AuditRegKeyName, $AuditValue);
            $GPOReportAlias.Add($GPOAlias, $AuditRegKeyName);

            #Get Reg Key for protection
            $RegKey = Get-RegistryKey $Entry;
            If($RegKey){
                $RegistryKeys += $RegKey;
            }
            $FileNameCount["Unmanaged"]++;
        }
    }

    #$x = Set-RegistryKeyValue -source "RegKeyAudit" -key $GPOPath -keyvalues $GPOReport -CVFormatted $true;                                               
    #Add-CustomVariables -xmlPath "RegKeyAudit" -keypath $AliasPath -aliasMap $GPOReportAlias -startClean $true;

}

Function Invoke-GetCurrentGPO{   
    $PolPaths = @{};
    $SystemPolPaths = Get-ChildItem -Path "$env:systemroot\System32\GroupPolicy\"  -Recurse -Force -Filter "registry.pol"
    $UserCount = 0;
    $MachineCount = 0;
    foreach($SystemPolFile in $SystemPolPaths){
        $ContextPath = $SystemPolFile.Directory.Name;
        if($ContextPath -eq "User"){
            $PolPaths.Add("User$UserCount", $SystemPolFile.FullName);
            $UserCount++;
        } elseif ($ContextPath -eq "Machine"){
            $PolPaths.Add("Machine$MachineCount", $SystemPolFile.FullName);
            $MachineCount++;
        }
    }

    $UserRegPaths = Get-ChildItem "$env:systemroot\System32\GroupPolicyUsers\" -Recurse -Force -Filter "*.pol";
    $SIDList = @{};
    foreach($UserPolFile in $UserRegPaths){
        $UserSID = $UserPolFile.DirectoryName;
        $UserSID = $UserSID.Replace("$env:systemroot\System32\GroupPolicyUsers\","").Replace("\User","");
        $UserName = Get-ReverseSID $UserSID;
        if(!($UserName.Contains("Error"))){
            $PolPaths.Add("User:$UserName", $UserPolFile.FullName);
            $SIDList.Add("User:$UserName", $UserSID);
        }
    }

    $CurrentValues = @();
    foreach($ContextVal in $PolPaths.Keys){
        $ContextPath = $PolPaths[$ContextVal];
        if($ContextVal -like "Machine*"){
            $Policies0 = Invoke-LGPO -LGPOArgs "/parse /m $ContextPath"
        } elseif($ContextVal -match "User\!(.*)"){
            $UserName = $Matches[1];
            $Policies0 = Invoke-LGPO -LGPOArgs "/parse /u:$UserName $ContextPath";
        } elseif($ContextVal -match "User[0-9]{0,3}"){
            $Policies0 = Invoke-LGPO -LGPOArgs "/parse /u $ContextPath";
        }
        if($Policies0[0]){
            $ParsePolicies = ConvertFrom-LGPOResults -LGPOContents $Policies0[1];
            $CurrentValues += $ParsePolicies;
        }
    }

    Start-RecordAudit -CurrentValues $CurrentValues;
}


Function Remove-GPOsFromLGPO {
    param([array]$Entries,[string]$source)
    $TempDeleteCache = "$current_path\Queue\$source`_delcache.txt"
    $RegistryKeys = @();
    $Removed = 0;
    If(Test-Path $TempDeleteCache){
        Remove-Item $TempDeleteCache;
    }
    ForEach($Entry in $Entries){
        $Collisions = Get-AuditEntries -Key "UID" -Search $UnmarkedEntry.UID
        If($Collisions.Count -eq 0){
            #Need to delete these entries
            $delkey = $Entry.Key;
            $delvaluename = $Entry.ValueName;
            $delcontext = $Entry.Context;
            $DelTemplate = "$delcontext`r`n$delkey`r`n$delvaluename`r`nDELETE`r`n`r`n"
            Add-Content $TempDeleteCache $DelTemplate

            $RegistryKey = Get-RegistryKey -Entry $Entry;
            $RegistryKeys += $RegistryKey;

            $Removed++;
        }
    }
    If(Test-Path $TempDeleteCache){
        Invoke-LGPO -LGPOArgs "/t $TempDeleteCache /v";
        Remove-Item $TempDeleteCache -Force;
    }


}

Function Open-LGPOProfile{
    param([string]$Filename)
    #Format the name of the file
    $ReadFile = [IO.File]::ReadAllText($Filename);
    If($ReadFile){
        If(!($ReadFile.contains("`s"))){
            $UnencryptedFile = ConvertFrom-EncryptedFile -FileContents $ReadFile;
            if($UnencryptedFile -and $UnencryptedFile -ne "Error"){
                Set-Content -Path $Filename -Value $UnencryptedFile;
                return $true;
            } 
        } Else{
            return $true;
        }
    } 
    return $false;
}

Function Start-ImportGPOFromLGPO
{
	param(
        $LGPOFile,
        $ProfileName="",
        [switch]$storeResults=$true
    )

    $ProfileId = $LGPOFile.BaseName;
    If(!($ProfileName)){
        $ProfileName = $ProfileId;
    }
    $Result = New-CustomVariableObj -Path "HKLM:\Software\AirWatch\ProductProvisioning\GroupPolicy" -ValueName "$ProfileName" -Alias "GPO.$ProfileName - STATUS" -Value "";

    If(!(Open-LGPOProfile -Filename $LGPOFile.FullName)){
        $Result.Value = "Open file error.";
        $OpenFileError = $true;
    }

    If(!($OpenFileError)){
        $AuditDatabase = Open-AuditDatabase -Path $AuditDatabase;
        $timestamp = (date).ToString("MM-dd-yyyy hh:mm:ss"); 

        $LGPOFileName = $LGPOFile.FullName;
        $LGPO_Import = Invoke-LGPO -LGPOArgs "/t $LGPOFileName /v";
        $LGPO_Record = ConvertFrom-LGPOResults $LGPO_Import;
   
        $Results = $AuditDatabase.SetEntries($ProfileId,$LGPO_Record,"UID","Value");
        if($Results.Updated){
            $AuditDatabase.Commit();
        }

        $UnmarkedEntries = @();
        $RemovedEntries = $Results.RemovedObjects;
        ForEach($RemoveEntry in $RemovedEntries){
            $Collisions = $AuditDatabase.GetEntries("","UID",$RemovedEntry.UID);
            if(($Collisions | measure).Count -eq 0){
                $UnmarkedEntries += $RemoveEntry;
            }
        }

        $Removed = Remove-GPOsFromLGPO -Entries $UnmarkedEntries -Source $ProfileId

        $RegKeys = ($LGPO_Record | where {$_.UID -notin ($RemoveEntry | select UID).UID} | Select RegKey).RegKey ;
        Add-AccessPolicy -Name $ProfileId -RegKeys $RegKeys; 
        $ResultStr = "SUCCESS  - " + ($Results | Select * -ExcludeProperty RemovedObjects | Format-Table | Out-String);
        $Result.Value = $ResultStr;
    }

    Set-CustomVariables -ProfileName $ProfileName -AliasObjects @($Result) -DisableAudit;

    if($LGPO_Import){
        return 1;
    } else {
        return 0;
    }
}

function Remove-ManagedGPOs{
    param([string]$ProfileName)    
    if(Test-Path -Path $AuditDatabase){
        $AuditDBJson = [IO.File]::ReadAllText($AuditDatabase);
        $AuditDB_Main = ConvertFrom-JSON -InputObject $AuditDBJson;
    } else{
        return $false;
    }

    $ProfileIndex = ([Collections.Generic.List[Object]]$AuditDB_Main.Profile).FindIndex({$args[0].Name -eq $ProfileName});
    If($ProfileIndex -lt 0){
        return $false;
    }
    $Profile = $AuditDB_Main.Profile | Where Name -EQ $ProfileName;
    
    Remove-GPOsFromLGPO -Entries $Profile.Entries -Source $ProfileName;
    $AuditDB_Main.Profile = $AuditDB_Main.Profile | Where Name -NE $ProfileName;

    $rawDB = ConvertTo-Json -InputObject $AuditDB_Main -Depth 10;
    Set-Content -Path $AuditDatabase -Value $rawDB;  

    return $true;
}

function Invoke-ProcessCommands{
    param([string]$commandfile)
    
    $Profiles = Get-AssignedAirWatchProfiles 

    $ValidProfileStatus = @(3,6);
    $InstalledProfiles = (($Profiles | Where Status -NotIn 3,6) | select Id).Id;
    $RemoveProfiles = ($AuditDB_Main.Profile | Select Name) | where {$_.Name -In $InstalledProfiles -and $_.Name -match "[0-9]{1,6}"};

    ForEach($RemoveProfile in $RemoveProfiles.Name){
        Remove-ManagedGPOs -ProfileName $RemoveProfile;
    }
    return $true;
}