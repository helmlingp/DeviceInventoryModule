#Get current path
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #default path if property not set
    $current_path = "C:\Temp\Shared";
}

#Set common folder locations 
$InstallPath = "HKLM:\Software\AIRWATCH\ProductProvisioning";
$shared_path = "C:\Temp\Shared" # default path if property not set
$shared_path = $current_path;

#setup log file
$logLocation = "C:\Temp\Logs\AirWatchAPI.log"; # default path if property not set
$log_path = Get-ItemPropertyValueSafe -Path $InstallPath -Name "LogPath" -DefaultVal "C:\Temp\Logs";
$logLocation = "$log_path\AirWatchAPI.log"; 

If(Test-Path $InstallPath){
    $getShared_path = ((Get-ItemProperty -Path $InstallPath).PSObject.Properties | where Name -eq "SharedPath") | Measure;
    If($getShared_path.Count -gt 0){
        $shared_path = Get-ItemPropertyValue -Path $InstallPath -Name "SharedPath"; 
        if($debug){
            Write-Log2 -Path $logLocation -Message "Shared Path $shared_path" -Level Info
        }
    }
} 

#Import Libraries and Functions
Unblock-File "$shared_path\Utility-Functions.psm1"
$module = Import-Module "$shared_path\Utility-Functions.psm1" -ErrorAction Stop -PassThru -Force;

if(Test-Path "$current_path\api-debug.config"){
    $useDebugConfig = $true;
}

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Get-AWAPIConfiguration{
    if(!$useDebugConfig){
        $api_config_file = [IO.File]::ReadAllText("$current_path\api.config");
        if($api_config_file.Contains('"ApiConfig"')){
            $api_settings = $api_config_file;
            $encrypted = ConvertTo-EncryptedFile -FileContents $api_config_file;
            if($encrypted){
                Set-Content -Path ("$current_path\api.config") -Value $encrypted;
            }
        } else {
            $Private:api_settings = ConvertFrom-EncryptedFile -FileContents $api_config_file;
        }
    } else {
          $api_config_file = [IO.File]::ReadAllText("$shared_path\api-debug.config");
          $Private:api_settings = $api_config_file;
    }
    $Private:api_settings_obj = ConvertFrom-Json -InputObject $Private:api_settings

    $Global:Server =  $Private:api_settings_obj.ApiConfig.Server;
    $Private:API_Key = $Private:api_settings_obj.ApiConfig.ApiKey
    $Private:Auth = $Private:api_settings_obj.ApiConfig.ApiAuth;
    $Global:OrganizationGroupId = $Private:api_settings_obj.ApiConfig.OrganizationGroupId;

    $content_type = "application/json;version=1";
    $content_type_v2 = "application/json;version=2";

    #$Private:Headers = @{"Authorization"=$Private:Auth;"aw-tenant-code"=$Private:API_Key;"accept"=$content_type;"content-type"=$content_type};
    #$Private:Headers_V2 = @{"Authorization"=$Private:Auth;"aw-tenant-code"=$Private:API_Key;"accept"=$content_type_v2;"content-type"=$content_type_v2};

    #DeviceId Getter
    If(![bool]($api_settings_obj.ApiConfig.PSobject.Properties.name -match "DeviceId")) {
        $Private:api_settings_obj.ApiConfig | Add-Member -MemberType NoteProperty -Name "DeviceId" -Value -1;
    } Else {
        If($api_settings_obj.ApiConfig.DeviceId -ne ""){
           $deviceid = $Private:api_settings_obj.ApiConfig.DeviceId;
        }
    } 

    #$Private:api_settings_obj | Add-Member -MemberType NoteProperty -Name "HeadersV1" -Value $Private:Headers;
    #$Private:api_settings_obj | Add-Member -MemberType NoteProperty -Name "HeadersV2" -Value $Headers_V2;

    return $api_settings_obj;
}

function Get-EnrollmentStatus{
    param([string]$DeviceId)

    Set-Variable -Name "api_settings_obj" -Value (Get-AWAPIConfiguration) -Scope "Private"

    $Server = $Private:api_settings_obj.ApiConfig.Server;

    Set-Content "C:\Temp\temp.log" -Value ($Private:api_settings_obj | Format-Table | Out-String)

    $serialSearch = wmic bios get serialnumber;
    $serialnumber = $serialSearch[2];
    $serialnumber = $serialnumber.Trim();

    $Enrolled = $true;
        
    $deviceEndpoint = "$Server/api/mdm/devices/$DeviceId";

    $currentDevice = Invoke-WebRequest -URI $deviceEndpoint -Headers $Private:api_settings_obj.HeadersV1 -UseBasicParsing;
    If($serialnumber -eq $currentDevice.SerialNumber){
        If($currentDevice.EnrollmentStatus -ne "Enrolled"){
            $deviceid = "";
            $Enrolled = $false;
        }
    } Else{
        $deviceid = "";
    }   
    return $Enrolled;
}

function Invoke-SecureWebRequest{
    param([string]$Endpoint, [string]$Method="GET", $ApiVersion=1, $Data, [bool]$Debug=$false)
    $Private:api_settings_obj = Get-AWAPIConfiguration;

    $SSLThumbprint = $Private:api_settings_obj.ApiConfig.SSLThumbprint;

    $Endpoint = $Endpoint.Replace("{DeviceId}",$Global:DeviceId).Replace("{OrganizationGroupId}",$Global:OrganizationGroupId);

    Try
    {
        # Create web request
        $WebRequest = [System.Net.WebRequest]::Create("$Global:Server/$Endpoint")
        $WebRequest.Method = $Method;

        #Setting Private Headers
        $WebRequest.Headers.Add("aw-tenant-code",$Private:api_settings_obj.ApiConfig.ApiKey);
        $WebRequest.Headers.Add("Authorization",$Private:api_settings_obj.ApiConfig.ApiAuth);
        
        #Setting Content
        $WebRequest.Accept = "application/json;version=$ApiVersion";
        $WebRequest.ContentType = "application/json;version=$ApiVersion";  
    
        #Data stream 
        If($Data){
            $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($Data);
            $WebRequest.ContentLength = $ByteArray.Length;  
            $Stream = $WebRequest.GetRequestStream();
            Try{              
                $Stream.Write($ByteArray, 0, $ByteArray.Length);   
            } Catch {
                $Error = $_.Exception.Message; 
            } Finally{
                $Stream.Close();
            }
        } Else {
            $WebRequest.ContentLength = 0;
        }

        # Set the callback to check for null certificate and thumbprint matching.
        $WebRequest.ServerCertificateValidationCallback = {
            $ThumbPrint = $SSLThumbprint;
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$args[1]
            
            If ($certificate -eq $null)
            {
                return $false
            }
 
            If (($certificate.Thumbprint -eq $ThumbPrint) -and ($certificate.SubjectName.Name -ne $certificate.IssuerName.Name))
            {
                return $true
            }
            return $false
        }      
        # Get response stream
        $Response = $webrequest.GetResponse();
        $ResponseStream = $webrequest.GetResponse().GetResponseStream()

        $SSLThumbPrint = $null;
        $Private:api_settings_obj = $null;

        # Create a stream reader and read the stream returning the string value.
        $StreamReader = New-Object System.IO.StreamReader -ArgumentList $ResponseStream
        
        Try{
            $Content = $StreamReader.ReadToEnd();
        } Catch {
            $Error = $_.Exception.Message;
        } Finally{
            $StreamReader.Close();
        }

        $CustomWebResponse = $Response | Select-Object Headers, ContentLength, ContentType, CharacterSet, LastModified, ResponseUri,
            @{N='StatusCode';E={$_.StatusCode.value__}},@{N='Content';E={$Content}}

        return $CustomWebResponse;
    }
    Catch
    {
        Write-Log2 -Path $logLocation -Message "Failed: $($_.exception.innerexception.message)" -Level Error
        $StatusCode = $_.Exception.InnerException.Response.StatusCode.value__;
        If(!($StatusCode)){
            $StatusCode = 999;
            $Content = $_.Exception.InnerException.Message;
        } ElseIf($_.Exception.InnerException.StatusCode.value__){
            $StatusCode = 999;
            $Content = $_.Exception.InnerException.Message;
        }
        return New-Object -TypeName PSCustomObject -Property @{"StatusCode"=$StatusCode;"Content"=$Content}
    } 

}

function Invoke-PrivateWebRequest{
    param([string]$Endpoint, $Method="Get", $ApiVersion=1, $Data, [bool]$Debug=$false)
    
    $Private:api_settings_obj = Get-AWAPIConfiguration;

    $Endpoint = $Endpoint.Replace("{DeviceId}",$Global:DeviceId).Replace("{OrganizationGroupId}",$Global:OrganizationGroupId);
    $WebRequest = $null;
    Try {
        $WebRequest = Invoke-WebRequest -Uri ("$Global:Server/$Endpoint") -Method $Method -Headers $Private:api_settings_obj."HeadersV$ApiVersion" -Body $Data -UseBasicParsing;
    } Catch{
        $ErrorMessage = $_.Exception.Message;
        If($Debug){ Write-Log2 -Message "An error has occurrred.  Error: $ErrorMessage" }
        if($_.Exception -like "Unable to connect to the remote server"){
            return "Offline";
        } 
    } Finally{
        $Private:api_settings_obj = $null;
    }

    return $WebRequest;
}

function Get-NewDeviceId{
    $Private:api_settings_obj = Get-AWAPIConfiguration;

    $Server = $Private:api_settings_obj.ApiConfig.Server;
    $Global:OrganizationGroupId = $Private:api_settings_obj.ApiConfig.OrganizationGroupId;
    $Global:deviceid = $Private:api_settings_obj.ApiConfig.DeviceId;

    $serialSearch = wmic bios get serialnumber;
    $serialnumber = $serialSearch[2];
    $serialnumber = $serialnumber.Trim();

    $serialEncoded = [System.Web.HttpUtility]::UrlEncode($serialnumber);
    $deviceSearchEndpoint = "api/mdm/devices?searchBy=Serialnumber&id=$serialEncoded";

    If($Private:api_settings_obj.ApiConfig.SSLThumbprint){      
        $WebResponse = Invoke-SecureWebRequest -Endpoint $deviceSearchEndpoint -Method $Method -ApiVersion 1 -Data $Data -Debug $Debug
    } Else{
        $WebResponse = Invoke-PrivateWebRequest -Endpoint $deviceSearchEndpoint -Method $Method -ApiVersion 1 -Data $Data -Debug $Debug
    }

    If($WebResponse.StatusCode -lt 300){
        If($WebResponse.Content){
            $device_json = ConvertFrom-Json($WebResponse.Content); 
        }
    }

    If($device_json.Id){
        $deviceid = $device_json.Id.Value;
        If ($device_json.EnrollmentStatus -ne "Enrolled"){
            return "Unenrolled";
        }
        $Private:api_settings_obj.ApiConfig.DeviceId = $device_json.Id.Value;
        #Save the Device id
        $apicontent = ConvertTo-Json $Private:api_settings_obj -Depth 10;
        If(!$useDebugConfig){
            $apiencryptedcontent = ConvertTo-EncryptedFile -FileContents $apicontent
            Set-Content "$current_path\api.config" -Value $apiencryptedcontent
        } Else {
            Set-Content "$current_path\api-debug.config" -Value $apicontent
        }
        $Global:deviceid = $device_json.Id;
       
        return $deviceid;
    } 
    return "Unenrolled";
}

function Invoke-AWApiCommand{
    param([string]$Endpoint, [string]$Method="GET", $ApiVersion=1, $Data, [bool]$Debug=$false)

    #Return Object set
    $ReturnObjectSet = @();

    #Load api config into private scope
    $Private:api_settings_obj = Get-AWAPIConfiguration;

    If(!($Private:api_settings_obj.ApiConfig.DeviceId) -and !($Global:DeviceId)){
        $CurrentDeviceId = Get-NewDeviceId;
        If($CurrentDeviceId -ne "Unenrolled"){
            $Global:DeviceId = $CurrentDeviceId
        }
    } Else{
        $Global:DeviceId = $Private:api_settings_obj.ApiConfig.DeviceId;
    }
    $Mode = 0;
    If($Private:api_settings_obj.ApiConfig.SSLThumbprint){
        $Private:api_settings_obj = $null;
        $WebRequest = Invoke-SecureWebRequest -Endpoint $Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug
        $Mode = 1;
    } Else{
        $Private:api_settings_obj = $null;
        $WebRequest = Invoke-PrivateWebRequest -Endpoint $Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug
    }
    
    If($Debug){
        Write-Log2 -Path $logLocation -Message "Connecting to: $Endpoint";
        If($WebRequest.Content){
            Write-Log2 -Path $logLocation -Message $WebRequest.Content;
        }
    }

    Try{ 
        if($WebRequest.StatusCode -lt 300){
           $ReturnObj = New-Object -TypeName PSCustomObject -Property @{"StatusCode"=$WebRequest.StatusCode};
           If($WebRequest.Content){
               $ReturnObj = ConvertFrom-Json($WebRequest.Content); 
               if($ReturnObj.Total){
                    if($ReturnObj.Total -gt ($ReturnObj.PageSize * ($ReturnObj.Page + 1)) -and $ReturnObj.PageSize -gt 0){
                        $ReturnObjectSet += $ReturnObj;
                        While($ReturnObj.Total -gt ($ReturnObj.PageSize * $ReturnObj.Page)){
                            If($Endpoint -match "([^?]*)\?"){
                                
                                $Page_Endpoint = $Endpoint + "&page=" + ($ReturnObj.Page + 1).ToString();
                            } Else{
                                $Page_Endpoint = $Endpoint + "?page=" + ($ReturnObj.Page + 1).ToString();
                            }

                            If($Mode -eq 1){
                                $WebRequest = Invoke-SecureWebRequest -Endpoint $Page_Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug
                            } Else{
                                $WebRequest = Invoke-PrivateWebRequest -Endpoint $Page_Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug
                            }
                            if($WebRequest.StatusCode -eq 200){
                                 $ReturnObj += (ConvertFrom-Json($WebRequest.Content)); 
                            }
                        }
                    }
               }
           } 
           return $ReturnObj;
        }
        else {
           return $WebRequest.Content;
        }
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        return (New-Object -TypeName PSCustomObject -Property @{"Error"="$ErrorMessage"});
    }
}

Export-ModuleMember -Function Invoke-AWApiCommand, ConvertTo-EncryptedFile, ConvertFrom-EncryptedFile, Get-AirWatchProfiles, Get-AWProfileCache
