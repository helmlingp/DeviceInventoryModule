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
$GlobalImporter = @("$shared_path\Database-Management.psm1", "$shared_path\AirWatchAPI.psm1",
                     "$shared_path\Utility-Functions.psm1");

foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$log_path\SmarterGroupsLogic.log"; 


$LocalCacheDBPath = "$current_path\Profiles\InstallList.db";

$SAFELevel = "3"
$UNSAFEKeywords = @("Function")
$SAFEApprovedCmndlets = @("Start-Sleep","Set-Location")
$SAFEApprovedVerbs = @("Where","Get","Find","Search","Select","Show","Compare","Read","Ping","Test","Trace","Measure","Debug","Wait","Request","ConvertTo","ConvertFrom");
$UNSAFEAliasList = (Get-Alias | where { $_.Definition -like "*-*" } | where { $_.Definition.Substring(0,$_.Definition.IndexOf("-")) -notin $SAFEApprovedVerbs } | select Name).Name

$i = 0;

function ConvertTo-DateTime{
    param([string]$Time, [datetime]$TimeSpanBase)
    #Accepted formats for date and time
    If($Time -eq "Now" -or !($Time)){
        #Support Now for DateTime
        return Get-Date;
    } ElseIf($Time -match "([1-9]{1}[0-9]{0,6})(s|m|h|d)" -and $TimeSpanBase){
        #Suppoerts short hand {number}{unit} for example 60s = 60 seconds
        if($Matches[2] -eq "s"){
            $TS = New-TimeSpan -Seconds $Matches[1]
        } elseif($Matches[2] -eq "m"){
            $TS = New-TimeSpan -Minutes $Matches[1]
        } elseif($Matches[2] -eq "h"){
            $TS = New-TimeSpan -Hours $Matches[1]
        } elseif($Matches[2] -eq "d"){
            $TS = New-TimeSpan -Days $Matches[1]
        } else{
            $TS = New-TimeSpan -Minutes 5
        }
        $EndTime = ($TimeSpanBase).Add($TS);
        return $EndTime;
    } Else {
        Try{
            $DateTimeConverter = [datetime]$Time;
            return $DateTimeConverter;
        } Catch {
            $ErrorMessage = $_.Exception.Message;
            Write-Log2 -Path $logPath -Message "An error has occured: $ErrorMessage";
        }
    }
    return;
}

function Get-SmarterGroupsTimerStatus{
    param([object]$Timer)
    $TimerDatabase = Open-AuditDatabase -Path "$current_path\Profiles\Timers.db"

    if(!$Timer){
        return 0;
    }

    if(!$Timer.EndTime){
        return 0;
    }

    if(!$Timer.TimerName){
        return 0;
    }
    $TimerName = $Timer.TimerName;
                     
    $CurrentTime = (Get-Date);
    $CurrentTimer = $TimerDatabase.GetEntries("ActiveTimers","TimerName",$TimerName);

    if($CurrentTimer){  
        $CurrentTimer = $CurrentTimer[0];
        if($CurrentTimer.Active -eq 0){
            return 0;
        }
        $StartTime = [DateTime]$currentTimer.StartTime;
        $EndTime = [DateTime]$currentTimer.EndTime;
    }

    If(!$StartTime) {
        $StartTime = ConvertTo-DateTime -Time $Timer.StartTime
    }

    If(!$EndTime){
        $EndTime = ConvertTo-DateTime -Time $Timer.EndTime -TimeSpanBase $StartTime;
    }

    if(!$CurrentTimer){
        $timerInfo = @{"TimerName"=$Timer.TimerName;"StartTime"=$StartTime.ToString();"EndTime"=$EndTime.ToString();"Active"=1};
        $currentTimer = New-Object -TypeName PSCustomObject -Property $timerInfo;
        $TimerDatabase.AddEntries("ActiveTimers",$CurrentTimer);
    }

    #After end time
    if(($CurrentTime).Subtract($EndTime).TotalSeconds -ge 0 -and $Timer.Active -eq "After"){
        $CurrentTimer.Active = 0;
    } elseif (($CurrentTime).Subtract($EndTime).TotalSeconds -le 0 -and 
        ($CurrentTime).Subtract($StartTime).TotalSeconds -ge 0  -and $Timer.Active -eq "During") {
        $CurrentTimer.Active = 0;
    } else {
        $CurrentTimer.Active = 1;
    }
    $TimerDatabase.Commit();
    $TimerDatabase.Close();
    return (1 - $CurrentTimer.Active);
}


function Get-AWItemStatus(){
    param($Cache, $Triggers)
    #Predefined triggers
    $Predefined = @("Timer","PowerShell");
    
    #Get initial set of items
    $Status = @{"Application"=@{"Uninstalled"=0;"Pending"=1;"Installed"=2};"Profile"=@{"Uninstalled"=0;"Error"=1;"Pending"=2;"Installed"=3;"InstallFailed"=6}}
    $check_pass = 0;
    $check_total = 0;
    $filter_count = 0;
    foreach($filterObj in $Triggers){
        $filter_count++;
        if($Predefined.Contains($filterObj.Type)){
            #Code area for predefined triggers
            if($filterObj.Type -eq "Timer"){  
                $check_total++;     
                
                $check_pass += Get-SmarterGroupsTimerStatus -Timer $filterObj;
          
            } elseif($filterObj.Type -eq "PowerShell"){
                $check_total++;
                If($filterObj.PSLogic){
                    if($SAFELevel -gt 0){
                        $PSResult = (Invoke-ExpressionSafe -Command $filterObj.PSLogic);
                    } else {
                        $PSResult = (iex $Tag.PSLogic);
                    }
                    If($PSResult){
                        $check_pass++
                    }
                }
            }
        } else {
            $item_search = $Cache[$filterObj.Type];
            foreach($filter in $filterObj.PSObject.Properties){
                $filterName = $filter.name;
                $filterValue = $filter.value;
                If($filterName -eq "Type"){
                    Continue;
                }
                $check_total++;
                $filterType = Get-AWFilterType $filterName $filterValue;
                $item_compare = "=";
                if($filterValue -eq "*"){
                    $check_pass++;
                } elseif($filterType -eq "String"){ 
                    $item_search = $item_search | where "$filterName" -Like $filterValue; 
                    if($item_search){
                        $check_pass++;
                    }
                } elseif($filterType -eq "Status"){
                    If($Status[$filterObj.Type].ContainsKey($filterValue)){
                        $item_search = $item_search | where "$filterName" -eq $Status[$filterObj.Type][$filterValue];
                        if($item_search){
                            $check_pass++;
                        }
                    }
                }
                elseif($filterType -eq "Version" -or $filterType -eq "Number"){  
                    if($filterValue -match "(\=|\<\=|\>\=|\>|\<)(.*)"){
                        $item_compare = $Matches[1];
                        $filterValue = $Matches[2];
                    }
                    if($filterType -eq "Version"){ 
                        $item_search | ForEach-Object {$_."$filterName" = [System.Version]$_."$filterName"}
                        $filterValue = [System.Version]$filterValue;
                    }

                    switch ($item_compare){
                       "=" { if($item_search | where "$filterName" -eq $filterVersion){ $check_pass++; } }
                       ">=" { if($item_search | where "$filterName" -GE $filterVersion){ $check_pass++; } }
                       "<=" { if($item_search | where "$filterName" -LE $filterVersion){ $check_pass++; } }
                       ">" { if($item_search | where "$filterName" -GT $filterVersion){ $check_pass++; } }
                       "<" { if($item_search | where "$filterName" -LT $filterVersion){ $check_pass++; } }
                    } 
                }
            }
        }
    }
    return $check_pass - $check_total;
}

function Get-AWFilterType(){
    param($filterName, $filterValue)
    if($filterName -Like "*Status*"){
        return "Status";
    } elseif($filterValue -match "[^.][\<\>\=][0-9]{1,16}$"){
        return "Number";
    } elseif($filterValue -match "[\<\>\=]{0,2}[0-9]{1,10}\.[0-9]{1,10}\.([0-9]{1,10}$|[0-9]{1,10}\.[0-9]{1,10}$)"){
        return "Version";
    } else {
        return "String";
    }
}

Function Test-WhatIf{
    param([string]$Cmndlet)
    Try{
        $Result = Invoke-Expression -Command ($Cmndlet + " -WhatIf")
    } Catch {
        $ErrorMessage = $_.Exception;
        If($ErrorMessage.ErrorId -eq "NamedParameterNotFound"){
            return $false;
        }
    }
    return $true;
}

Function Invoke-ExpressionSafe{
    param([string]$Command,[bool]$Debug=0)
    Try{
        #Parse cmndlet
        ForEach($kw in $UNSAFEKeywords){
            $kw = $kw.ToLower();
            If($Command.ToLower() -contains $kw){
                if($Debug){  Write-Log2 -Path $logLocation -Message "Error: Unsafe keyword detected - $Command contains $kw."}
                return "Error: Unsafe keyword detected";
            }
        }
        ForEach($usa in $UNSAFEAliasList){
            If($Command.ToLower() -match "(^|[\s]|[\r\n]|[\t])$usa([\s]|[\r\n]|[\t])"){
                if($Debug){  Write-Log2 -Path $logLocation -Message "Error: Unsafe alias detected - $Command contains $usa." }
                return "Error: Unsafe alias detected";
            }
        }

        $Cmndlets = Select-String "([A-Za-z]{1,})\-[A-Za-z0-9{1,}]*" -input $Command -AllMatches | Foreach {$_.matches}

        ForEach($CmndletMatch in $Cmndlets){
            ForEach($CmndletGroup in $CmndletMatch.Groups){
                $MyMatch = $CmndletGroup.Value;
                If($MyMatch.Contains("-")){
                    $CmndletItem = $MyMatch;
                    If(Test-WhatIf -Cmndlet $CmndletItem){
                        if($Debug){ Write-Log2 -Path $logLocation -Message "Error: Unsafe keyword detected - $Command contains -WhatIf attribute associated with unsafe Cmndlets." }
                        return "Error: Unsafe cmndlt detected, -WhatIf present"; 
                    }
                } Else{
                    $VerbItem = $MyMatch;
                    If($VerbItem -notin $SAFEApprovedVerbs){
                        if($Debug){  Write-Log2 -Path $logLocation -Message "Error: Unsafe keyword detected - $Command contains $VerbItem" }
                        return "Error: Unsafe verb detected"
                    }
                }
            }
        }
        return (Invoke-Expression -Command $Command);
    } Catch {
        $ErrorMessage = $_.Exception.Message;
         if($Debug){ Write-Log2 -Path $logLocation -Message "An error has occured: $ErrorMessage" }

    }
}

$bulk_items = @"
{
    "BulkValues": {
    "Value": [
        $deviceId
    ]
    }
}
"@


Function Get-DeviceTags{
    $deviceid = $Global:DeviceId;
    $device_tag_endpoint = "api/mdm/devices/$deviceid/tags";

    $Tags = Invoke-AWApiCommand -Endpoint $device_tag_endpoint
    If($Tags.Tag){
        $LocalCacheDB = Open-AuditDatabase -Path $LocalCacheDBPath -Encrypted;
        $TagData = $LocalCacheDB.GetEntries("Tags");
        If(($TagData | measure).Count -gt 0){ 
            $TagData = $TagData | Select * -Unique;
            $TagData | % {
                $CurrentId = $_.Id;
                $CurrentTag = $Tags.Tag | where {$_.Id.Value -eq $CurrentId};
                If($CurrentTag -and $_.Status -notlike "Added*"){
                    $_.Status = "Added:1";
                } ElseIf(!($CurrentTag) -and $_.Status -like "Added"){
                    $_.Status = "Removed:1";
                }
            };

            $NewTags = $Tags.Tag | where {$_.Id.Value -notin ($TagData | Select Id).Id}; 
            $TagData += ($NewTags | select @{N='ID';E={$_.Id.Value}},@{N='Status';E={"Added:1"}})
        } Else{
            $TagData += ($Tags.Tag | select @{N='ID';E={$_.Id.Value}},@{N='Status';E={"Added:1"}})
        }
        $Result = $LocalCacheDB.SetEntries("Tags",$TagData);
        If($LocalCacheDB.Status -eq 2){
            $LocalCacheDB.Commit($true);
        }
        $LocalCacheDB.Close();
        return $Tags.Tag;
    } ElseIf($Tags.StatusCode){
        If($Tags.StatusCode -lt 300){
            return @("None");
        }
    } 
    return $null;
}

Function Set-SmartGroupResults{
    param([bool]$Result, $TagId, $NewOrganizationGroupId, $TagCache, [switch]$IsStatic, [switch]$Debug)
        #Load global API configurations
        If(!($TagCache)){
            $OrganizationGroupId = $Global:OrganizationGroupId;
            $deviceid = $Global:DeviceId;
        }
        #Set API endpoints 
        $og_search_endpoint = "api/system/groups/search";
        $device_endpoint = "api/mdm/devices/$deviceid/";
        $addDeviceEndpoint = "api/mdm/tags/{tagid}/adddevices";
        $removeDeviceEndpoint = "api/mdm/tags/{tagid}/removedevices";
        $change_og_endpoint = "api/mdm/devices/$deviceid/commands/changeorganizationgroup/";
        
        $Status = "Unknown";
        If($TagId){  
            #Open the local cache
            If(!($TagCache)){
                $LocalCacheDB = Open-AuditDatabase -Path $LocalCacheDBPath -Encrypted;
                $CurrentTag = $LocalCacheDB.GetEntries("Tags","Id",$TagId); 
                if(!$CurrentTag){     
                    $NewTag = New-Object -TypeName PSCustomObject -Property @{"Id"=$TagId;"Status"="Unknown"};
                    $LocalCacheDB.AddEntries("Tags",$NewTag);
                    $CurrentTag = $LocalCacheDB.GetEntries("Tags","Id",$TagId)[0];
                } Else{
                    $CurrentTag = $CurrentTag[0];
                }

            } Else{
                $CurStatus = "Removed:2";
                $GetTagStatus = $TagCache | where {$_.Id.Value -eq $TagId}
                If(($GetTagStatus | measure).Count -gt 0){
                    $CurStatus = "Added:2";
                }
                $CurrentTag = New-Object -TypeName PSCustomObject -Property @{"Id"=$TagId;"Status"=$CurStatus};
            }


            If ($Result -eq $true -and $CurrentTag.Status -like "Added*"){
                $CurrentTag.Status = "Added:1";
            } ElseIf($Result -eq $false -and $CurrentTag.Status -like "Removed*"){
                $CurrentTag.Status = "Removed:1"
            } ElseIf($Result -eq $true -and $CurrentTag.Status -notlike "Added*"){ 
                $add_tags = Invoke-AWApiCommand -Method Post -Endpoint ($addDeviceEndpoint.Replace("{tagid}",$tag_id)) -Data $bulk_items;
                if($add_tags.TotalItems){
                    if($add_tags.AcceptedItems -eq 1){
                            $CurrentTag.Status = "Added:0";
                    } elseif ($add_tags.FailedItems -eq 1 -and 
                            $add_tags.Faults.Fault[0].ErrorCode -eq 400){
                            $CurrentTag.Status = "Added:2";
                    }
                }       
            } ElseIf($Result -eq $false -and $CurrentTag.Status -notlike "Removed*"){                      
                If(!($Tag.Static)){
                    $remove_tags = Invoke-AWApiCommand -Method Post -Endpoint ($removeDeviceEndpoint.Replace("{tagid}",$tag_id)) -Data $bulk_items;
                    if($remove_tags.TotalItems){
                        if($remove_tags.AcceptedItems -eq 1){
                                $CurrentTag.Status = "Removed:0";
                        } elseif ($remove_tags.FailedItems -eq 1 -and 
                                $remove_tags.Faults.Fault[0].ErrorCode -eq 400){
                                $CurrentTag.Status = "Removed:2";
                        }
                    }
                } 
            }
            If(!($TagCache)){
                $Updates = $LocalCacheDB.SetEntries("Tags",$CurrentTag,"Id","Status",$false)
                if($Updates.Updated){
                    $LocalCacheDB.Commit();
                }
                $LocalCacheDB.Close();
            }
            $myResult = $CurrentTag.Status; 
        } ElseIf ($NewOrganizationGroupId -and $Result){
            $ogmove = Invoke-AWApiCommand -Method Put -Endpoint ($change_og_endpoint + "$NewOrganizationGroupId") 
            If($ogmove){
                $myResult = "OrgGroup:0"
            }
        }


        return $myResult;
}


Export-ModuleMember -Function Invoke-ExpressionSafe, Get-AWItemStatus, Set-SmartGroupResults, ConvertTo-DateTime, Get-DeviceTags