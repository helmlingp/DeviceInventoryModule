<#

#>
$logLocation = "C:\Temp\Logs\Access.log";
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Shared";
}

Unblock-File "$current_path\Security-Functions.psm1"
$module = Import-Module "$current_path\Security-Functions.psm1" -ErrorAction Stop -PassThru -Force;

If(Test-Path "C:\Temp\accesspolicies.access"){
    $RawData = [IO.File]::ReadAllText("C:\Temp\accesspolicies.access");
    $Access = ConvertFrom-Json -InputObject $RawData;
}
ElseIf(Test-Path "$current_path\accesspolicies.access"){
    $RawData = [IO.File]::ReadAllText("$current_path\accesspolicies.access");
    $Access = ConvertFrom-Json -InputObject $RawData;
} Else{
    $Access = New-Object -TypeName PSCustomObject -Property @{"Access"=@{}}
}


$current_user = Get-CurrentLoggedonUser -ReturnObj $true;

If(!$Access.SecurityLevel){
    return;
} ElseIf($Access.SecurityLevel -eq 0){
    return;
} ElseIf($Access.SecurityLevel -gt 0){
    $Debug = $false;
    $DebugLogging = $false;
    If($Access.SecurityLevel -lt 2){
        $Debug = $true;
    }
    If($Access.SecurityLevel -lt 3){
        $DebugLogging = $true;
    }
    ##########################################################
    #Get the list of users to block
    $CustomUserListChange = $false;
    $UserList = @("Users");
    If($Access.AccessUsers){
        If($Access.AccessUsers.Count -gt 0){
            $UserList = $Access.AccessUsers
        } 
    } elseif($Access.AccessRules){
        $UserList = @();
        ForEach($AccessRule in $Access.AccessRules){
            If($AccessRule.AccessLogic){
                $AccessLogic = $AccessRule.AccessLogic;
                $AccessUsers = @();
                $AllUsers = Get-AllKnownUsers;
                $AccessUsers += $AllUsers;
                If($DebugLogging){
                    Write-Log2 -Path $logLocation -Message ("Get all users: `r`n " + ($AccessUsers | Format-Table | Out-String));
                }
                ForEach($Rule in $AccessLogic){
                    $RuleString = "";
                    If($Rule.Group){
                        $CurrentRuleGroup = Get-UserGroup -Name $Rule.Group;
                        $RuleString = "Current rule is: " + $Rule.Rule + " user group, " + $CurrentRuleGroup;
                        $AccessUsers = Get-UsersInGroup -Group $CurrentRuleGroup.Name -GroupDomain $CurrentRuleGroup.Domain -SearchType $Rule.Rule -Users $AccessUsers;
                    } ElseIf($Rule.User){
                        $UsersCheck = @();
                        $UsersCheck += $Rule.User;
                        $RuleString = "Current rule is: " + $Rule.Rule + " user list, " + ($UsersCheck | Format-List | Out-String);
                        if($Rule.Rule -EQ "NOTIN"){
                             $AccessUsers = $AccessUsers | where {$_.Name -notin $UsersCheck -or $_.FullName -notin $UsersCheck}         
                        } elseif ($Rule.Rule -EQ "IN") {
                             $AccessUsers = $AccessUsers | where {$_.Name -in $UsersCheck -or $_.FullName -in $UsersCheck} 
                        }
                    }
                    If($DebugLogging){
                        Write-Log2 -Path  $logLocation -Message ($RuleString + "`r`n" +
                              ($AccessUsers | Format-Table | Out-String));
                    }
                }
                
                If(($AccessUsers | Measure).Count -gt 0){
                    $UserList += ($AccessUsers | Select FullName).FullName;
                } 
            }
        }
    }



    ################################################

    If(Test-Path "$current_path\Archive.db"){
        $Data = [IO.File]::ReadAllText("$current_path\Archive.db");
        $AccessDB = ConvertFrom-Json $Data;
    } Else {
        $AccessDB = New-Object -TypeName PSCustomObject -Property @{"Archive"=@()};
    }
    If(!$AccessDB.Archive){
        $AccessDB = New-Object -TypeName PSCustomObject -Property @{"Archive"=@()};
    } Else{
        If(($AccessDB.Archive.GetType()).BaseType.ToString() -ne "System.Array"){
            $AccessDB = New-Object -TypeName PSCustomObject -Property @{"Archive"=@()};
        }
    }

    $BlockPaths = @();
    $BlockAccessPaths = @();
    If($Access.BlockList){
        #Ensure BlockAccess to Install paths
        ForEach($ListItem in $Access.BlockList){
            $AccessRights = "Default";
            If($ListItem.Type){
                If($ListItem.Name -eq "Install"){
                    $AccessRights = "Max";
                }
            }
            If($ListItem.Paths){
                $BlockAccessPaths += New-FolderUserAccessObj -AccessPaths $ListItem.Paths -UserList $UserList -RightLevel $AccessRights -DebugLog $DebugLogging;
            }
            If($ListItem.RegKeys){  
                $BlockAccessPaths += New-FolderUserAccessObj -AccessPaths $ListItem.RegKeys -UserList $UserList -DebugLog $DebugLogging;
            }
        }
        $new_paths = $BlockAccessPaths | select Path, NewRight, Type, @{N='UserAccess';E={
                $_.UserAccess | Select Allowed, @{N='Denied';E={ @() } } } } |
                where {$_.UserAccess | where {($_.Allowed | measure).Count -gt 0}};

        $validated =  $BlockAccessPaths | select Path, NewRight, Type, @{N='UserAccess';E={ 
                    $_denied = $_.UserAccess.Denied | where -Property User -In $UserList;
                    $_.UserAccess | Select @{N='Allowed';E={ @() }}, @{N='Denied';E={ $_denied } } } } |
                    where {$_.UserAccess | where {($_.Denied | measure).Count -gt 0}};

        $Test = @();
        $orphaned_users =  $BlockAccessPaths | select Path, NewRight, Type, @{N='UserAccess';E={ 
                    $_denied = $_.UserAccess.Denied | where -Property User -NotIn $UserList;
                    $_.UserAccess | Select @{N='Allowed';E={ @() }}, @{N='Denied';E={ $_denied } } } } |
                    where {$_.UserAccess | where {($_.Denied | measure).Count -gt 0}};

        If($new_paths -and $DebugLogging){
            Write-Log2 -Path $logLocation -Message ($new_paths | Format-List | Out-String);
        }
        $dbchange = $false;
        If($new_paths){
            $BlockResults = @();
            $BlockResults = Set-FolderUserAccess -AccessPathSet $new_paths -Action RemoveAccess -DebugMode $Debug -DebugLog $DebugLogging;
            $BlockResultsStore = ($BlockResults | where {$_.ResultStatus -eq "SUCCESS" -and 
                $_.Path -notin $AccessDB.Archive} | select Path).Path;
            If($BlockResultsStore){
                $AccessDB.Archive += $BlockResultsStore;
                $dbchange = $true;
            }
        }    
        if($validated){
            $validatedStore = ($validated | where {$_.Path -notin $AccessDB.Archive} | select Path).Path;
            If($validatedStore){
                $AccessDB.Archive += $validatedStore;
                $dbchange = $true;
            }
        }
    }

    if($dbchange){
        $AccessDBJson = ConvertTo-Json -InputObject $AccessDB -Depth 10;
        Set-Content -Path "$current_path\Archive.db" -Value $AccessDBJson;    
    }

    $AllowPaths = @();
    $AllowAccessPaths = @();
    $AllowResults = @();
    if($orphaned_users){
        $AllowPaths += $orphaned_users;
    }
  
    #Loop to get allow paths
    If($Access.AllowList){
        ForEach($ListItem in $Access.AllowList){
            If($ListItem.Paths){
                $AllowAccessPaths += New-FolderUserAccessObj -AccessPaths $ListItem.Paths -UserList $UserList -RightLevel $AccessRights -DebugLog $DebugLogging;
            }
            If($ListItem.RegKeys){  
                $AllowAccessPaths += New-FolderUserAccessObj -AccessPaths $ListItem.RegKeys -UserList $UserList -DebugLog $DebugLogging;
            }
        }       
    }

    
    #This gets paths that are in the archive but are no longer on the block or allow list
    $AccessDB.Archive | Where {$_ -notin ($BlockAccessPaths | select Path).Path -and $_ -notin ($AllowAccessPaths | select Path).Path}
    If($OrphanedPaths){
        $AllowPaths += New-FolderUserAccessObj -AccessPaths $OrphanedPaths -UserList $UserList -DebugLog $DebugLogging;
    }

    $allow_new_paths = $AllowAccessPaths | select Path, NewRight, Type, @{N='UserAccess';E={ 
            $_denied = $_.UserAccess.Denied | where -Property User -NotIn $UserList;
            $_.UserAccess | Select @{N='Allowed';E={ @() }}, @{N='Denied';E={ $_denied } } } } |
            where {$_.UserAccess | where {($_.Denied | measure).Count -gt 0}}
    If($allow_new_paths){
        $AllowPaths += $allow_new_paths
    }
    If($allow_new_paths -and $DebugLogging){
        Write-Log2 -Path $logLocation -Message ($allow_new_paths | Format-List | Out-String);
    }
    If($AllowPaths.Count -gt 0){
        $AllowResults =  Set-FolderUserAccess -AccessPathSet $AllowPaths -Action RestoreAccess -DebugMode $Debug -DebugLog $DebugLogging;
        $AllowDBResults = $AccessDB.Archive | where {$_ -notin ($AllowResults | select Path).Path}
        If($AllowDBResults){
            $AccessDB.Archive = $AllowDBResults;
            $AccessDBJson = ConvertTo-Json -InputObject $AccessDB -Depth 10;
            Set-Content -Path "$current_path\Archive.db" -Value $AccessDBJson; 
        }
    }
}