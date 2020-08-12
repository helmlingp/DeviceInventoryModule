<#
    Copyright [2017] [Chase Bradley]
#>
#==========================Header=============================#
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\GroupPolicy";
}

Unblock-File "$current_path\Helpers.psm1"
$LocalHelpers = Import-Module "$current_path\Helpers.psm1" -ErrorAction Stop -PassThru -Force;

$shared_path = $Global:shared_path;


$GlobalModules = @();
$GlobalImporter = @("$current_path\Import_Types_Ex.psm1","$shared_path\Utility-Functions.psm1")
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}
$InstallPath = "HKLM:\Software\AIRWATCH\ProductProvisioning";

$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$log_path\GroupPolicyLogs.log";        

#These are the designated folders to process the .CSV files
$cache = "$current_path\Queue";
If(!(Test-Path $cache)){
    New-Item -Path "$current_path\Queue" -ItemType Directory -Force
} 

If(!(Test-Path $cache)){
    New-Item -Path "$current_path\Audit" -ItemType Directory -Force
}


Function Import-GroupPolicyFiles{
    param([switch]$NoReconcile)
    #Check for uninstall requests
    Invoke-ProcessCommands

    #Configure supported file types
    #Currently only supports CSVs from the export and Zip files containing the exports
    $supportedFileTypes = @("txt");

    Write-Log2 -Path $logLocation -Message "Beginning Import Group Policy"
    #Main thread
    $fileProcessor = @{}
    $processZip = 0;

    $processing = Get-ChildItem $cache -Recurse
    ForEach ($policyFileSys in $processing) { 
	    $policyFile = $policyFileSys.FullName;
        Write-Log2 -Path $logLocation -Message ("Parsing file: " + $policyFileSys.FullName)
        if($policyFileSys.Extension -eq ".txt"){
            #Modern import
            $parse = Start-ImportGPOFromLGPO -LGPOFile $policyFileSys;
        } else {
            continue;
        }
        if($parse -eq 1){
            #Remove-Item $policyFile;
        }
    }
    Invoke-GetCurrentGPO;
}

Function Initialize-Reconcile{
     Start-ReconcileUserAccess;
}

Add-Type @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Win32.API {

    public class GroupPolicy {

        public GroupPolicy(){}
        [DllImport("Userenv.dll", SetLastError=true)]
        public static extern bool RefreshPolicyEx(
            bool bMachine,
            string dwOptions
           );


        public bool RefreshMachinePolicy(){
            if(RefreshPolicyEx(true, "RP_FORCE")){
                return RefreshPolicyEx(false, "RP_FORCE");
            }
            return false;
        }
        
        
    }
}
"@;

Function Initialize-GPRefresh{
    #Force GPUpdates
    Write-Log2 -Path $logLocation -Message "Import complete.  Updating gpt.ini files."
    Try{
        $GroupPolicy = New-Object Win32.API.GroupPolicy;
        $UseGPUpdate = $GroupPolicy.RefreshMachinePolicy();
    } Catch{

    }
    if(!$UseGPUpdate){
        GPUpdate.exe /force
    }
}


Import-GroupPolicyFiles;
Initialize-GPRefresh;