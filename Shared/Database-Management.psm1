$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Shared\";
}

Unblock-File "$current_path\Utility-Functions.psm1"
$module = Import-Module "$current_path\Utility-Functions.psm1" -ErrorAction Stop -PassThru -Force;

$logLocation = "C:\Temp\Logs\UtilitiesLogs.log";
$securityLogLocation = "C:\Temp\Logs\SecurityAudit.log";

$DatabaseRegPath = "HKLM:\Software\AirWatch\ProductProvisioning\DatabaseAccess"
If(!(Test-Path $DatabaseRegPath)){
    New-Item -Path $DatabaseRegPath -Force;
}

Enum DatabaseStatus{
    Closed = 0
    Open = 1
    UncommittedData = 2
}


Class AuditDatabase{
    
    [DatabaseStatus]$Status;
    [string]$DatabaseRegName;
    [string]$DatabaseRegPath = "HKLM:\Software\AirWatch\ProductProvisioning\DatabaseAccess";
    [string]$Path;
    [object]$DB; 
    [bool]$Encrypted;

    SetStatus([DatabaseStatus]$Status){
        $Now = (Get-Date).ToString();
        $this.Status = $Status;
        New-ItemProperty -Path $this.DatabaseRegPath -Name $this.DatabaseRegName -Value $this.Status.value__ -Force;
        New-ItemProperty -Path $this.DatabaseRegPath -Name ($this.DatabaseRegName + "_LastUpdate") -Value $Now -Force;
    }


    AuditDatabase([string]$Path, [bool]$Encrypted){
        $this.Encrypted = $Encrypted;
        $this.Path = $Path;
        $this.DatabaseRegName = Split-Path -Path $Path -Leaf;
        if(Test-Path -Path $Path){
            $AuditDBJson = [IO.File]::ReadAllText($Path);
            If($Encrypted){
                $AuditDBJson = ConvertFrom-EncryptedFile -FileContents $AuditDBJson;
            }
            $this.DB = ConvertFrom-JSON -InputObject $AuditDBJson;
        } else{
            $this.DB = New-Object PSCustomObject -Property @{"Profile"=@()}  
        }
        $this.SetStatus([DatabaseStatus]::Open);
    }


    [object]GetProfile([string]$ProfileName){     
        $ContextSearch = $this.DB.Profile | where {$_.Name -eq $ProfileName};
        if($ContextSearch){
            return $ContextSearch;
        }
        return $false;
    }

    [object]AddProfile([string]$ProfileName){
        $DBRef = $this.DB;
        if(!($DBRef.Profile | where {$_.Name -eq $ProfileName})){
            $ContextProperties = @{"Name"=$ProfileName;"Entries"=@()}
            $ContextObj = New-DynamicObject -Properties $ContextProperties;

            $DBref.Profile += $ContextObj;
            $AuditProfile = $DBRef.Profile | where {$_.Name -eq $ProfileName};
            $this.SetStatus([DatabaseStatus]::UncommittedData);
            return $AuditProfile;                
        }
        return $false;
    }

    [bool]RemoveProfile([string]$ProfileName){
        $DBRef = $this.DB;
        $DBRef.Profile = $DBRef.Profile | where {$_.Name -ne $ProfileName};
        $this.SetStatus([DatabaseStatus]::UncommittedData);  
        return $true;
    }

    [array]GetEntries([string]$ProfileName){
        $Entries = @();
        If($ProfileName){
            $DBRef = $this.DB;
            $Profile = $DBRef.Profile | where {$_.Name -eq $ProfileName};
            $Entries = $Profile.Entries;
        }
        return $Entries;
    }
    
    [array]GetEntries([string]$ProfileName="",$Key,[string]$Search){
        $DBRef = $this.DB;
        $Entries = @{}; 

        $Keys = @();
        $Keys += $Key;
        #Allows dynamic use of properties to determine unique key id
        $KeyBuilder = "";
        $Keys | % { If($KeyBuilder){ $KeyBuilder += " + '&' + "; } $KeyBuilder += "`$_." + $_; } 

        #Creates the script blocks nessecary
        $KeyScript = [scriptblock]::Create( $KeyBuilder )
        
        Try{
            If($ProfileName){
                $Profile = $DBRef.Profile | where {$_.Name -eq $ProfileName};
                #Get current count of entries
                $Entries = $Profile.Entries | Select *, @{N='UniqueKey';E=$KeyScript} | 
                    Where {$_.UniqueKey -eq $Search} | Select * -ExcludeProperty UniqueKey;
            } Else {

                #Get current count of entries
                $Entries = ($DBref.Profile | select @{N='FlatEntries';
                     E={$ProfileName = $_.Name;$_.Entries | Select *,@{N="ProfileName";E={$ProfileName}}}}).FlatEntries |
                     Select *, @{N='UniqueKey';E=$KeyScript} | 
                     where {$_.UniqueKey -eq $Search};
                If(($Entries | Measure).Count -gt 0){
                     $Entries = $Entries | Select * -ExcludeProperty UniqueKey
                }
            }
        } Catch {
            $ExceptionMessage = $_.Exception.Message;
        }
        return $Entries;
    }

    [bool]AddEntries([string]$ProfileName="",$Entries){
        $Profile = $this.GetProfile($ProfileName);
        If(!$Profile){
            $Profile = $this.AddProfile($ProfileName);
        } 

        Try{
            If($Profile.Entries.GetType().BaseType.Name -ne "Array"){
                $SavedEntry = $Profile.Entries[0];
                $Profile.Entries = @($SavedEntry);
            }
        
            $Profile.Entries += $Entries;
            $this.SetStatus([DatabaseStatus]::UncommittedData);
        } Catch{
            return $false;
        }
        return $true;
    }
    
    [int]RemoveEntries([string]$ProfileName="",$Key,[string]$Search){
        $DBRef = $this.DB;
        $Entries = @{}; 

        $Keys = @();
        $Keys += $Key;
        #Allows dynamic use of properties to determine unique key id
        $KeyBuilder = "";
        $Keys | % { If($KeyBuilder){ $KeyBuilder += " + '&' + "; } $KeyBuilder += "`$_." + $_; } 

        #Creates the script blocks nessecary
        $KeyScript = [scriptblock]::Create( $KeyBuilder )

        $DeletedEntries = 0;
        Try{
            #For deleting entries under a specific profile vs. across all profiles
            If($ProfileName){
                $Profile = $DBRef.Profile | where {$_.Name -eq $ProfileName};
                #Get current count of entries
                $EntryCount = ($Profile.Entries | Mesure).Count;
                $Profile.Entries = $Profile.Entries | Select *, @{N='UniqueKey';E=$Keys} | 
                    Where {$_.UniqueKey -ne $Search} | Select * -ExcludeProperty UniqueKey;
                $DeletedEntries += ($EntryCount - ($Profile.Entries | Mesure).Count)
            } Else {
                ForEach($Profile in $DBRef.Profile){
                    $EntryCount = ($Profile.Entries | Mesure).Count;
                    $Profile.Entries = $Profile.Entries | Select *, @{N='UniqueKey';E=$Keys} | 
                    Where {$_.UniqueKey -ne $Search} | Select * -ExcludeProperty UniqueKey;
                    $DeletedEntries += ($EntryCount  - ($Profile.Entries | Mesure).Count);
                }
            }
        } Catch {
            $ExceptionMessage = $_.Exception.Message;
        }
        If(($DeletedEntries | measure).Count){
            $this.SetStatus([DatabaseStatus]::UncommittedData);
        }
        return $DeletedEntries;
    }

    [object]SetEntries([string]$ProfileName,[object]$Entries){
        $Profile = $this.GetProfile($ProfileName);
        If(!$Profile){
            $Profile = $this.AddProfile($ProfileName);
        }
        $ResultsObject = New-Object -TypeName PSCustomObject -Property @{"Updated"=$true};

        $Profile.Entries = $Entries;

        $this.SetStatus([DatabaseStatus]::UncommittedData);

        return $ResultsObject;
    }
    
    
    [object]SetEntries([string]$ProfileName,[object]$Entries,$Key,$Value,$RemoveEmpty=$false){
        $Profile = $this.GetProfile($ProfileName);
        If(!$Profile){
            $Profile = $this.AddProfile($ProfileName);
        }

        $Keys = @();
        $Keys += $Key;
        #Allows dynamic use of properties to determine unique key id
        $KeyBuilder = "";
        $Keys | % { If($KeyBuilder){ $KeyBuilder += " + '&' + "; } $KeyBuilder += "`$_." + $_; } 

        $Values = @()
        $Values += $Value;
        #Allows dynamic use of properties to determine value
        $ValueBuilder = "";
        $Values | % { If($ValueBuilder){ $ValueBuilder += " + '&' + "; } $ValueBuilder += "`$_." + $_; } 

        #Creates the script blocks nessecary
        $KeyScript = [scriptblock]::Create( $KeyBuilder )
        $ValueScript = [scriptblock]::Create( $ValueBuilder )


        #Creates an Index for the dynamic keys and values
        $CurrentEntryIndex = $Profile.Entries | select *,@{N='UniqueKey';E=$KeyScript},@{N='UValue';E=$ValueScript};
        $NewEntryIndex = ($Entries | select *,@{N='UniqueKey';E=$KeyScript},@{N='UValue';E=$ValueScript});

        #Removes entries not passed allong within the set
        $CurrentEntries = ($CurrentEntryIndex | select *,@{N='UniqueKey';E=$KeyScript}) | 
            where {$_.UniqueKey -in ($NewEntryIndex | select UniqueKey).UniqueKey};
        $RemovedEntries = @();
        $RemovedEntriesCount = 0;
        if($RemoveEmpty){
            $RemovedEntries = ($CurrentEntryIndex | select *,@{N='UniqueKey';E=$KeyScript}) | 
                where {$_.UniqueKey -notin ($NewEntryIndex | select UniqueKey).UniqueKey};
            $RemovedEntriesCount = ($CurrentEntryIndex | Measure).Count - ($CurrentEntries | Measure).Count;
        
        }
        If($RemovedEntriesCount -gt 0){
            $Profile.Entries = @();
            $Profile.Entries += $CurrentEntries | Select-Object * -ExcludeProperty UniqueKey,UValue;
        }
        
        If($Profile.Entries){
            If($Profile.Entries.GetType().BaseType.Name -ne "Array"){
                $SavedEntry = $Profile.Entries[0];
                $Profile.Entries = @($SavedEntry);
            }
        }

        #Get the new entries and adds them to the DB
        $NewEntries = ($NewEntryIndex | select *,@{N='UniqueKey';E=$KeyScript}) | 
            where {$_.UniqueKey -notin ($CurrentEntryIndex | select UniqueKey).UniqueKey};
        If(($NewEntries | Measure).Count -gt 0){
            $Profile.Entries += $NewEntries | select -Property * -ExcludeProperty UniqueKey, UValue;
        }

       
        $EntryValueCheck = @();
        $ModifiedCount = 0;
        #Sets the value of modified entries to the new entry
        ($Profile.Entries | Select *, @{N='UniqueKey';E=$KeyScript},@{N='UValue';E=$ValueScript} | % {
            $CurrentKey = $_.UniqueKey;
            $CurrentItem = $_;
            $NewItem = $NewEntryIndex | where UniqueKey -eq $CurrentKey;
            If(($NewItem | measure).Count -gt 0){            
                if($NewItem.UValue -ne $_.UValue){
                    $CurrentItem = $NewItem | Select * -ExcludeProperty UniqueKey,Uvalue; 
                    $ModifiedCount++;
                }   
            }
            $EntryValueCheck += $CurrentItem | Select * -ExcludeProperty UniqueKey,Uvalue;
        }) 
        
        If($ModifiedCount -gt 0){
            $Profile.Entries = $EntryValueCheck;
        }

        $Total = ($ModifiedCount + ($NewEntries | Measure).Count + $RemovedEntriesCount);
        $ResultsObject = New-Object -TypeName PSCustomObject -Property @{"New"=($NewEntries | Measure).Count;
            "Modified"=$ModifiedCount;"Removed"=$RemovedEntriesCount;"Total"=$Total;
            "RemovedObjects"=($RemovedEntries | Select * -ExcludeProperty UniqueKey,UValue)};

        $Updated = $false;
        If($Total -gt 0){
            #Changes made
            $this.SetStatus([DatabaseStatus]::UncommittedData);
            $Updated = $true;
        } 
        return ($ResultsObject | Select *,@{N='Updated';E={$Updated}});
    }

    [object]SetEntries([string]$ProfileName,[object]$Entries,$Key,$Value){
        $results =  $this.SetEntries($ProfileName,$Entries,$Key,$Value,$true);
        return $results;
    }

    Commit(){
        $this.Commit($false);
    }

    Commit([bool]$Compress){
        $DBJson = ConvertTo-Json $this.DB -Depth 10 -Compress:($Compress);
        If($this.Encrypted){
            $DBJson = ConvertTo-EncryptedFile -FileContents $DBJson;
        }
        Set-Content $this.Path $DBJson -Force;
        $this.SetStatus([DatabaseStatus]::Open);
    }

    Close(){
        $this.SetStatus([DatabaseStatus]::Closed);
        $this.DB = $null;
    }
}


Function Open-AuditDatabase{
    param([string]$Path, [switch]$Encrypted, [int]$MaxTimeout=10)
    $Timer = 0;
    $Now = Get-Date;
    $DatabaseRegName = $Path | Split-Path -Leaf
    While($true){
        $CurrentTime = Get-Date;
        $DatabaseStatus = Get-ItemPropertyValueSafe -Path $DatabaseRegPath -Name $DatabaseRegName -DefaultVal 0
        If($DatabaseStatus -eq 0 -or $Timer -gt ($MaxTimeout * 1000)){
            break;
        } ElseIf($DatabaseStatus -ne 0){
            $LastUpdate = [datetime](Get-ItemPropertyValueSafe -Path $DatabaseRegPath -Name ($DatabaseRegName + "_LastUpdate" ) -DefaultVal $Now);
            If(($CurrentTime.Subtract($LastUpdate)).TotalSeconds -gt $MaxTimeout){
                break;
            }
        }
        Sleep -Milliseconds 500;
        $Timer += 500;
    }
    $AuditDatabase = [AuditDatabase]::new($Path,($Encrypted.IsPresent));

    return $AuditDatabase;
}



# Export the function, which can generate a new instance of the class
Export-ModuleMember -Function Open-AuditDatabase