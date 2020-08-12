$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Shared\";
}

Unblock-File "$current_path\Utility-Functions.psm1"
$module = Import-Module "$current_path\Utility-Functions.psm1" -ErrorAction Stop -PassThru -Force;

$logLocation = "C:\Temp\Logs\UtilitiesLogs.log";
$securityLogLocation = "C:\Temp\Logs\SecurityAudit.log";
$FileRightLookup = @{"FileWriteLock"=852350;"FullControl"="FullControl";}
$RegRightLookup = @{"RegWriteLock"=852006;"RegReadLock"=131081;"ReadKey"="ReadKey";"WriteKey"="WriteKey";"FullControl"="FullControl";"Delete"="Delete"};

Function ConvertTo-ParsedUserFormat{
    param([string]$Username)
    $usernameLookup = $Username;
    $localmachineLookup = @(".","local");
    $localmachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
    if($usernameLookup -match "([^\\]*)\\(.*)"){
        $usernameProp = @{"Username"=$Matches[2];"Domain"=$Matches[1];"FullName"=$Matches[0]}  
    } elseif($usernameLookup -match "([^@]*)@(.*)"){
        $usernameProp = @{"Username"=$Matches[1];"Domain"=$Matches[2];"Fullname"=$Matches[0]}
    } else{ 
        $usernameProp =  @{"Username"=$usernameLookup;"Domain"=$localmachine;"Fullname"="$localmachine\$usernameLookup"}
    }
    $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
    If($usernameLookup.Domain -in $localmachineLookup){
        $usernameLookup.Domain = $localmachine
    }

    return $usernameLookup

}


<#
Function: Get-UserAccessStatus
Author  : cbradley@vmware.com
Description : Sets permissions on folder
Input Params:         
      Output: Bool
Example: Set-RegistryPermissionAccess
        returns Chase Bradley
#>
function Get-UserAccessStatus{
    Param([string]$Path,$Userlist,[bool]$VerboseLogging=$false)
    $Users = @();
    $Users += $Userlist;
        
    $ResultsProp = @{"Allowed"=@();"Denied"=@();"Errors"=@{}};
    $ResultsObj = New-Object -TypeName PSCustomObject -Property $ResultsProp;

    if($Users.Count -eq 0){
        $Users += "User";
    }

    Try{
        $localmachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
        $getItem = (Get-Item $Path -Force -ErrorAction Stop)
        $getAccessList = $getItem.GetAccessControl('Access');
        $FormattedAccessList = $getAccessList.Access | Select-Object *, @{Name='Name';
            Expression={$_.IdentityReference.Value.Replace("NT AUTHORITY",$localmachine).Replace("BUILTIN",$localmachine) } };
        $UserGroupMap = Get-CimInstance "Win32_GroupUser"
    } Catch{
        $ResultsObj.Errors.Add("*",$ErrorMessage);
        Write-Log2 -Path $securityLogLocation -Message "An error has occured getting access list of path, $Path :$ErrorMessage" -Level Error;
    }
       
    foreach($AccessUser in $Users){
        Try{
            if($VerboseLogging){
                Write-Log2 -Path $securityLogLocation -Message "Getting access information of user $User at location $Path";
            }
            $AllowCount = 0;
            $BlockCount = 0;
            $Mode = "UserMode";
            $ParsedUser = ConvertTo-ParsedUserFormat -Username $AccessUser
            If((($UserGroupMap | where {$_.GroupComponent.Name -EQ $ParsedUser.Username -and 
                $_.GroupComponent.Domain -EQ $ParsedUser.Domain}) | measure).Count -gt 0){
                $Mode = "GroupMode";
            }
            $AccessList =  $FormattedAccessList | 
                where {$_.Name -EQ $ParsedUser.Fullname}
            If($AccessList){
                $AllowCount += ($AccessList | where {$_.AccessControlType.ToString() -eq "Allow"} | measure).Count; 
                $BlockCount += ($AccessList | where {$_.AccessControlType.ToString() -eq "Deny"} | measure).Count; 
            }
                      
            If($Mode -eq "UserMode"){
                $CurrentUserGroupList = $UserGroupMap | where {$_.PartComponent.Name -EQ $ParsedUser.Username -and 
                    $_.PartComponent.Domain -EQ $ParsedUser.Domain} | select @{Name='FullName';Expression={
                        $_.GroupComponent.Domain + "\" + $_.GroupComponent.Name};
                    }                
                $UserAccessList = $FormattedAccessList  | where {$_.Name -in ($CurrentUserGroupList | select FullName).FullName }
                If($UserAccessList){
                    $AllowCount += ($UserAccessList | where {$_.AccessControlType.ToString() -eq "Allow"} | measure).Count; 
                    $BlockCount += ($UserAccessList | where {$_.AccessControlType.ToString() -eq "Deny"} | measure).Count; 
                }
            }
            If($VerboseLogging){
                Write-Log2 -Path $securityLogLocation -Message "User: $AccessUser, has $BlockCount DENY RULES and $AllowCount ALLOW RULES at $Path";
            }

            If($BlockCount -gt 0 -or $AllowCount -eq 0){
                $ResultsObj.Denied += $AccessUser;
            } Else{
                $ResultsObj.Allowed += $AccessUser;
            } 
        }
        Catch{
            $ErrorMessage = $_.Exception.Message;
            Write-Log2 -Path $SecurityLogLocation -Message "An error has occured getting access list of path, $Path for user, $AccessUser : $ErrorMessage" -Level Error;
            $ResultsObj.Errors.Add($AccessUser,$ErrorMessage);
        }
        
    } 
    return $ResultsObj;
}




Function Set-SystemOwner{
    param([string]$Path)
    Try{
        $currentAccessList = (Get-Item $Path -Force).GetAccessControl('Access');
        $objUser = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM") 
        if($currentAccessList.Owner -ne "NT AUTHORITY\SYSTEM"){  
            #if($currentAccessList.Owner){
                 $currentAccessList.SetOwner($objUser);
            #}
        }
        Set-Acl -path $Path -AclObject $currentAccessList -ErrorAction Stop; 
        return $true;
    } Catch{
        $errorMessage = $_.Exception.Message;
        Write-Log2 -Path $securityLogLocation -Message "$errorMessage"; 
    }
    return $false;
}

<#
Function: Set-FolderPermissionAccess
Author  : cbradley@vmware.com
Description : Sets permissions on folder
Input Params: $Path: [String], folder or file path that we are changing the permissions on
              $UserList: [Array]
              $Action=: [String] "Set" 
                Must be Set, Remove or Remove All
              $Access="Modify"
              $Right="Deny"
                
      Output: [HashTable]{[array]Changes,[hashtable]Error}
Example: Set-FolderPermissionAccess
        returns Chase Bradley
#>
function Set-FolderPermissionAccess{
    [CmdletBinding()]
    
    Param(
        [Parameter(Mandatory=$true,ParameterSetName="Dir")]
        [Alias('Path')]
        [string]$FilePath,
        [array]$UserList,
        [Parameter(Mandatory=$true,ParameterSetName="Reg")]
        [string]$RegistryPath="Set",
        [Parameter(Mandatory=$false)]
        [ValidateSet("Remove","RemoveAll","Set")]
        [string]$Action="Set",
        [string]$Access,
        [ValidateSet("Allow","Deny")]
        [string]$Right="Deny",
        [bool]$DebugLog=$false,
        [bool]$CommitChanges=$true
    )

    if(!$UserList){ return; }
    $Path = $FilePath
    $Access = $Access;
    $Type = $psCmdlet.ParameterSetName;
    if($psCmdlet.ParameterSetName -eq "Reg"){
        $Path = $RegistryPath;
    }

    if(Test-Path $Path){
        If($DebugLog){
            Write-Log2 -Path $securityLogLocation -Message "SECURITY: Applying permissions to path, $Path";
        }
    } else{
        $results["ErrorList"].Add("PathError","Error: Path, $Path does not exist");
        return $results;
    }

    $currentAccessList = (Get-Item $Path -Force).GetAccessControl('Access');
   
    $timestamp = (date).ToString("MM-dd-yyyy hh:mm:ss"); 
    $resultArray = @();
    #Ensure that we are running under the system context     
    foreach($AccessUser in $UserList){
        if(!$AccessUser){
            Continue;
        } elseif($AccessUser -Match "System" -or $AccessUser -eq "$env:COMPUTERNAME"){
            Continue;
        } 
        $SUCESSLIST = @();
        Try{
            $Audit = "SECURITY: Performing $Action for new $Right rule, $Access for $AccessUser using context: $env:Username";
            If($DebugLog){ Write-Log2 -Path $securityLogLocation -Message $Audit; }
            
            $inherit = 'ContainerInherit,ObjectInherit';
            if((Get-Item $Path -Force).GetType().Name -match "File|Directory|RegistryKey"){
                 if((Get-Item $Path -Force).GetType().Name -eq "FileInfo"){ $inherit = 'None'; } 
                    if($psCmdlet.ParameterSetName -eq "Reg"){
                         $Ar0 = New-Object System.Security.AccessControl.RegistryAccessRule($AccessUser, $Access,
                            $inherit, 'None', $Right);
                    } Else{
                         $Ar0 = New-Object System.Security.AccessControl.FileSystemAccessRule($AccessUser, $Access,                 
                            $inherit, 'None', $Right) 
                    }   
                    Switch($Action) {
                       "Set"  {
                        $currentAccessList.SetAccessRule($Ar0);
                    } "Remove" {
                        $currentAccessList.RemoveAccessRule($Ar0);
                    } "RemoveAll" {
                        $currentAccessList.RemoveAccessRuleAll($Ar0);
                    }
                  }
                $success = "SECURITY: $Action $AccessUser" + ":$Access" +  ":$Right - SUCCESS";
                If($DebugLog){ Write-Log2 -Path $securityLogLocation -Message $success; }
                $SUCESSLIST += $AccessUser;
            } 
        } Catch {
            $errorMessage = $_.Exception.Message;
            Write-Log2 -Path $securityLogLocation -Message "Error setting user rights: $errorMessage" -Level Error; 
            $resultStatus = "ERROR"; 
        }
    }
    If($CommitChanges){
        Try {
            $result = Set-Acl -path $Path -AclObject $currentAccessList; 
            $resultStatus = "SUCCESS";
        } Catch{
            $errorMessage = $_.Exception.Message;
            Write-Log2 -Path $securityLogLocation -Message "Error setting user rights: $errorMessage" -Level Error;
            $resultStatus = "ERROR"; 
        }   
    } Else{
        If($DebugLog){
            Write-Log2 -Path $securityLogLocation -Message "SECURITY: Commit disabled.";
            $C = Start-Transcript $securityLogLocation -Append;
            Set-Acl -path $Path -AclObject $currentAccessList -WhatIf;
            $S = Stop-Transcript;
            $resultStatus = "TESTED";
        }
    }
    
    $localmachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
    $FormattedAccessList = $currentAccessList.Access | Select-Object *, @{N='Name';
    E={$_.IdentityReference.Value.Replace("NT AUTHORITY",$localmachine).Replace("BUILTIN",$localmachine) } } |
    Where {$_.Name -in $UserList};
    $UserAccessObj = ($FormattedAccessList | Select-Object @{N='User'; E={$_.Name}}, @{N='IdentityReference';E={$_.IdentityReference}},
       @{N='Access'; E={$_.AccessControlType}} ,
       @{N='Rights'; E={If($_.FileSystemRights){ $_.FileSystemRights } Else {  $_.RegistryRights }}}
       
    );
    $ResultsProp = @{'Path'=$Path ; 'Type'=$Type; 'NewRights'="";'ResultStatus'=$resultStatus;'UserAccess'=$UserAccessObj };
    $ResultsObj = New-Object -TypeName PSCustomObject -Property $ResultsProp;

    return $ResultsObj;
}



Function Get-AirWatchInstallLocation{
    $airwatchInstallDir = "C:\Program Files (x86)\AirWatch\";
    If(Test-Path "HKLM:\Software\AirWatch"){
        If(Test-ItemProperty -Path "HKLM:\Software\AirWatch" -Name "INSTALLDIR"){ 
            $airwatchInstallDir = Get-ItemPropertyValue -Path "HKLM:\Software\AirWatch" -Name "INSTALLDIR";
        }
    }
    return $airwatchInstallDir;
}



Function Get-IdentityReference{
    param([string]$Identity,[bool]$IsGroup)
    #Format of Domain\Username

    If($Identity -match "[^\\]\\(.*)"){
        $IdentityReference = $Matches[1];
    } Else{
        $IdentityReference = $Identity;
    }

    If($IsGroup){
        $Groups = (Get-CimInstance -ClassName Win32_Group) | where Caption -EQ $Identity
        If(($Groups | measure).count -eq 1){
            $SID = ($Groups | Select SID).SID
            Try{
                $mySID = New-Object System.Security.Principal.SecurityIdentifier($SID)
                $IdentityReference = $mySID.Translate([System.Security.Principal.NTAccount]).value  
            } Catch{
                $IdentityReference = ($Groups | select Name).Name
            }
        }  
    } Else{
        Try{
            $User = New-Object System.Security.Principal.NTAccount($Identity)
            $sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value 
            $IdentityReference = $Identity;
        } Catch{
            #Do nothing
        } 
    }
    return $IdentityReference;
}

<#
Function: List-CurrentPermission
Author  : cbradley@vmware.com
Description : Lists permissions of an object
Input Params: N/A, Output: String
Example: List-CurrentPermission
        logs permissions in secuirtyAudit.log 
#>
function Get-CurrentPermissions{
    Param([string]$Path,[string]$Filter,[array]$UserList,[bool]$DebugLog)
    Try{
        $localmachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
        $getItem = (Get-Item $Path -Force -ErrorAction Stop)
        $currentAccessList = $getItem.GetAccessControl('Access');
        $FormattedAccessList = $currentAccessList.Access | Select-Object *, @{Name='Name';
            Expression={$_.IdentityReference.Value.Replace("NT AUTHORITY",$localmachine).Replace("BUILTIN",$localmachine) } };
        $UserGroupGet = Get-CimInstance "Win32_GroupUser";
        $UserGroupMap = $UserGroupGet | Select-Object @{N='Group';E={$_.GroupComponent.Domain + "\" + $_.GroupComponent.Name}},
                @{N='User';E={$_.PartComponent.Domain + "\" + $_.PartComponent.Name}} | Group-Object Group | Select Name, 
                @{N='Users';E={$_.Group.User}};
 
    } Catch{
        $errorMessage = $_.Exception.Message;
        Write-Log2 -Path $securityLogLocation -Message "Error gettings access to $Path, $errorMessage" -Level Error;
        return;
    }
    If($DebugLog){
        Write-Log2 -Path $securityLogLocation -Message "LISTING RIGHTS for: $Path";
    }
    If($Filter){
        $FormattedAccessList = $FormattedAccessList | where {$_.AccessControlType -eq $Filter}
    }
    $Type = "Dir"
    If($FormattedAccessList | where {$_.RegistryRights}){
        $Type = "Reg"
    }
    $DenyList = @();
    $DenyACL = ($FormattedAccessList | Select-Object @{N='User'; E={$_.Name}},@{N='IdentityReference';E={$_.IdentityReference}},
       @{N='Access'; E={$_.AccessControlType}} ,
       @{N='Rights'; E={If($_.FileSystemRights){ $_.FileSystemRights } Else {  $_.RegistryRights }}}
    );
    $DenyList += $DenyACL;
    If($DenyList){
        $UserList = $UserList | where {$_ -notin ($DenyList | select User).User};
        $UserGroupCheck = $DenyList | Where {$_.User -in ($UserGroupMap | select Name).Name} 
        If(($UserGroupCheck | Measure).Count -gt 0){
            $UserGroupCheck = $UserGroupCheck | select Name,@{N='Users';E={$_.Users | where {$_ -in $UserList}}} | where {$_.Users}
            $UserList = $UserList | where {$_ -notin ($Test | Select Users).Users}
        }
    }
    $AllowList = @();
    ForEach($User in $UserList){
       $IsGroup = ($User -in ($UserGroupMap | Select Name).Name);
       $IdentityReference = Get-IdentityReference -Identity $User -IsGroup $IsGroup;
       $AccessObjProp = @{"User"=$User;"IdentityReference"=$IdentityReference;"Access"="Allow";"Rights"=""}
       $AccessObj = New-Object -TypeName PSCustomObject -Property $AccessObjProp;
       $AllowList += $AccessObj;
    }
    $SummaryProp = @{"Denied"=$DenyList;"Allowed"=$AllowList} 
    $SummaryObj = New-Object PSCustomObject -Property $SummaryProp
    If($DebugLog){
        Write-Log2 -Path $securityLogLocation -Message ($SummaryObj | Format-Table | Out-String);
    }
   
    return $SummaryObj;
}

Function ConvertTo-EnvironmentString{
    param([string]$myString)
    If($myString -match "(\`$env\:([^\\]*))\\.*"){
        $environmentVar = Get-ChildItem Env: | where Name -eq $Matches[2];
        If($environmentVar){
            $myString = $myString.Replace($Matches[1], $environmentVar.Value);
        }
    }
    return $myString;
}

Function New-FolderUserAccessObj {
    param($AccessPaths,
          $UserList,
          $RightLevel="Default",
          $DebugLog=$false)
    $RightMap = @{'DirMin'='Write';'DirDefault'=852350;'DirMax'='FullControl';
        'RegMin'='Write';'RegDefault'=852006;'RegMax'=852006;
    }


    $AccessResults = @();
    $AccessPathArray = @();
    $AccessPathArray += $AccessPaths;
    ForEach($AccessPath in $AccessPathArray){
        If($AccessPath){
            $ValueName = "";
            $Path = $AccessPath;
            $PathType = "Dir";
            If($AccessPath -match "((HKLM\:|HKU\:|HCU\:)\\[^!]*)(\!(.*)|$)"){
                If($Matches.Count -eq 5 -and $Matches[4]){
                    $ValueName = $Matches[4]; 
                }
                $Path = $Matches[1];
                $PathType = "Reg";
            } Else {
                $Path = ConvertTo-EnvironmentString $Path;
            }
            
            $Right = $RightMap["$PathType$RightLevel"];
            If(Test-Path $Path){
                $UserAccess = Get-CurrentPermissions -Path $Path -UserList $UserList -Filter "Deny" -DebugLog $DebugLog;
                $AccessProp = @{'Path'=$Path;'NewRight'=$Right;'Type'=$PathType;'UserAccess'=$UserAccess} 
                $AccessObj = New-Object -TypeName PSCustomObject -Property $AccessProp            
                $AccessResults += $AccessObj;
            }
        }
    }
    return $AccessResults;
   
}

Function Set-FolderUserAccess{
    Param($AccessPathSet,
         [ValidateSet("RemoveAccess","RestoreAccess")]
         [string]$Action="RemoveAccess",
         [Parameter(Mandatory=$false)]
         [array]$UserList,
         [bool]$DebugMode=$false,
         [bool]$DebugLog=$false)
    $timestamp = (date).ToString("MM-dd-yyyy hh:mm:ss"); 
    $resultSet = @();
    $Command = "Set";
    If($Action -eq "RestoreAccess"){
        $Command = "Remove";
    }
    foreach($AccessPathEntry in $AccessPathSet){
        #For Overriding using standard use
        If($UserList){
            $SetUserList = $UserList
        } Else{
            $UnsetUsers = @();
            If($Action -eq "RestoreAccess" -and ($AccessPathEntry.UserAccess.Denied | Measure).Count -gt 0){
                $SetUserList = ($AccessPathEntry.UserAccess.Denied | select IdentityReference).IdentityReference;
                $Right = "FullControl";                        
            } ElseIf($Action -eq "RemoveAccess" -and ($AccessPathEntry.UserAccess.Allowed.Count | Measure).Count -gt 0){
                $SetUserList = ($AccessPathEntry.UserAccess.Allowed | select IdentityReference).IdentityReference;
                $UnsetUsers = ($AccessPathEntry.UserAccess.Denied | select IdentityReference).IdentityReference;
                $Right = $AccessPathEntry.NewRight;
            } Else{
                continue;
            }
        }
        

        If($AccessPathEntry.Type -eq "Dir"){                       
            $resultSet += Set-FolderPermissionAccess -Path $AccessPathEntry.Path -Action $Command -UserList $SetUserList -Access $Right -Right Deny -DebugLog $DebugLog -CommitChanges (!$DebugMode)
        } ElseIf($AccessPathEntry.Type -eq "Reg"){
            $resultSet += Set-FolderPermissionAccess -RegistryPath $AccessPathEntry.Path -Action $Command -UserList $SetUserList -Access $Right -Right Deny -DebugLog $DebugLog -CommitChanges (!$DebugMode)
        }
        #ForEach($UnsetUser in $UnsetUsers){
        #    $resultsProp = @{"Timestamp"=$timestamp;"User"=$UnsetUser;"Path"=$AccessPathEntry.Path;"Value"="$Command->$Right->Deny";"Status"="SUCCESS(NC)";}
        #    $resultsObj = New-Object -TypeName PSCustomObject -Property $resultsProp;
        #    $resultSet += $resultsObj;
        #}
 
        #$current_permission = Get-CurrentPermissions -Path $AccessPathEntry.Path -DebugLog $DebugLog;
    }
    return $resultSet;
}
     
     


function Get-Hash{
    param([string]$TextToHash)
    $hasher = new-object System.Security.Cryptography.MD5CryptoServiceProvider
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash)
    $hashByteArray = $hasher.ComputeHash($toHash)
    foreach($byte in $hashByteArray)
    {
      $result += "{0:X2}" -f $byte
    }
    return $result;
 }


 function Add-AccessPolicy{
    param([string]$Name, [array]$Paths=@(), [array]$RegKeys=@(), 
         [ValidateSet("AllowList","BlockList")]
         [string]$AccessList="BlockList")
    
    If(Test-Path -Path "$current_path\accesspolicies.access"){
        $RawData = [IO.File]::ReadAllText("$current_path\accesspolicies.access");
        $accesspolicies = ConvertFrom-Json -InputObject $RawData;
    } Else {
        $accesspolicies = New-Object -TypeName PSCustomObject -Property @{$AccessUsers=@("Users");$BlockList=@();$AllowList=@()};
    }
    $NewItem = New-Object -TypeName PSCustomObject -Property @{"Name"=$Name;"Type"="Profile";"Paths"=$Paths;"RegKeys"=$RegKeys}

    $CurrentItem = $accesspolicies."$AccessList" | where Name -EQ $Name;
    If(($CurrentItem | measure).Count -eq 1){
        If($AccessList -eq "BlockList"){
            $original_paths = $CurrentItem.Paths | where {$_ -notin $Paths};
            $original_regkeys = $CurrentItem.RegKeys | where {$_ -notin $RegKeys};
        }
        $CurrentItem.Paths = $Paths;
        $CurrentItem.RegKeys = $RegKeys;
    } else {
        $accesspolicies."$AccessList" += $NewItem;
    }

    $convertedJson = ConvertTo-Json $accesspolicies -Depth 10;
    Set-Content "$current_path\accesspolicies.access" $convertedJson;

    $TestAccessTask = (Get-ScheduledTask -TaskName "Apply_AccessPolicies" -TaskPath "\AirWatch MDM\" -ErrorAction Ignore | Measure).Count;
    If($TestAccessTask -gt 0){
        Start-ScheduledTask -TaskName "Apply_AccessPolicies" -TaskPath "\AirWatch MDM\";
    }
 }

 Function Remove-AccessPolicyItems{
    param([string]$AccessPolicyName,[string]$AccessList="BlockedList",[array]$Paths,[array]$RegKeys)
   
    If(Test-Path -Path "$current_path\accesspolicies.access"){
        $RawData = [IO.File]::ReadAllText("$current_path\accesspolicies.access");
        $accesspolicies = ConvertFrom-Json -InputObject $RawData;
    }

    $CurrentItem = $accesspolicies."$AccessList" | where Name -EQ $AccessPolicyName;

     If(($CurrentItem | measure).Count -eq 1){
        If($AccessList -eq "BlockList"){
            $diffPaths = $CurrentItem.Paths | where {$_ -notin $Paths};
            $diffRegKeys = $CurrentItem.RegKeys | where {$_ -notin $RegKeys};
            If($diffPaths.Count -gt 0 -or $diffRegKeys -gt 0){
                $CurrentItem.Paths = $diffPaths;
                $CurrentItem.RegKeys = $diffRegKeys;
            } Else {
                
            }
        }
    } else {
        $accesspolicies."$AccessList" += $NewItem;
    }
    
 }