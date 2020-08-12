
$InstallPath = "HKLM:\Software\AIRWATCH\ProductProvisioning";
$shared_path = "C:\Temp\Shared"
$LogPath = "C:\Temp\Logs";
$InstallPathDirs = @();

If(Test-Path $InstallPath){
    $getShared_path = ((Get-ItemProperty -Path $InstallPath) | where Name -eq "SharedPath") | Measure;
    If($getShared_path.Count -gt 0){
        $shared_path = Get-ItemPropertyValue -Path $InstallPath -Name "SharedPath";       
    }
    $InstallPathDirs += ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -like "*IPath" | Select Value).Value
    $LogPath = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -like "*LogPath" | Select Value).Value 
}
$InstallPathDirs += $LogPath;

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
    Set-Content -Path "$shared_path\accesspolicies.access" -Value $AccessJson

    If((Get-ScheduledTask | where {$_.TaskName -eq "Apply_AccessPolicies" -and 
            $_.TaskPath -eq "\AirWatch MDM\"} | measure).Count -gt 0){
        Start-ScheduledTask -TaskName "Apply_AccessPolicies" -TaskPath "\AirWatch MDM\";
    }

}

$RegKeys = @("HKLM:\SOFTWARE\AIRWATCH\GroupPolicy","HKLM:\SOFTWARE\AIRWATCH\InventorySettings","HKLM:\SOFTWARE\AIRWATCH\ProductProvisioning");
ForEach($myKey in $RegKeys){
    If(Test-Path $myKey){
        Remove-Item -Path $myKey -Recurse -Force;
    }
}

ForEach($myPath in $InstallPathDirs){
    If(Test-Path $myPath){
        Remove-Item -Path $myPath -Recurse -Force;
    }
}

$Tasks = (Get-ScheduledTask) | where {$_.TaskPath -eq "\AirWatch MDM\"}
ForEach($Task in $Tasks){
    Unregister-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -Confirm:$false
}

If(Test-Path "C:\Program Files (x86)\AirWatch\AgentUI\Cache\Profiles"){
    Remove-Item -Path "C:\Program Files (x86)\AirWatch\AgentUI\Cache\Profiles" -Recurse
}