<#
    File: Import_CustomSettings.ps1
    Author: cbradley@vmware.com
	Modified by Phil Helmling: 5 December 2019, optimised and restructured to reduce API calls
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
$logLocation = "$Global:log_path\AirWatchAPI.log"; 

$GlobalModules = @();
$GlobalImporter = @("$shared_path\Utility-Functions.psm1")
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

function Get-AWAPIConfiguration{
	param([bool]$Debug)
	If($Debug) {
		Write-Log2 -Path "$logLocation" -Message "Get device attributes from api.config" -Level Info
		Write-Log2 -Path "$logLocation" -Message "---------------------------------------------------------------------------" -Level Info
	}
	if(Test-Path "$Global:shared_path\api-debug.config"){
		$useDebugConfig = $true;
		#$Debug = $true;
	}
	#Read api.config file and return as object
	if(!$useDebugConfig){
        $Private:api_config_file = [IO.File]::ReadAllText("$Global:shared_path\api.config");
		If ($Debug) {
			Write-Log2 -Path "$logLocation" -Message "api_config_file: $Global:shared_path\api.config" -Level Info
		}
		#Encrypt api.config if not already (test to read if 'ApiConfig' exists)
        if($Private:api_config_file.Contains('"ApiConfig"')){
            $Private:api_settings = $Private:api_config_file;
            $encrypted = ConvertTo-EncryptedFile -FileContents $Private:api_config_file;
            if($encrypted){
                Set-Content -Path ("$Global:shared_path\api.config") -Value $encrypted;
            }
        } else {
			#If already enrypted, read into ConvertFrom-EncryptedFile function to decrypt
			$Private:api_settings = ConvertFrom-EncryptedFile -FileContents $Private:api_config_file;
        }
    } else {
        If ($Debug) {
			Write-Log2 -Path "$logLocation" -Message "api_config_file: $Global:shared_path\api-debug.config" -Level Info
		}
		$Private:api_config_file = [IO.File]::ReadAllText("$Global:shared_path\api-debug.config");
        $Private:api_settings = $Private:api_config_file;
    }
    $Private:api_settings_obj = ConvertFrom-Json -InputObject $Private:api_settings
	
    $content_type = "application/json;version=1";
    $content_type_v2 = "application/json;version=2";

    #If DeviceId property doesn't exist in the api.config file then add it
    If(![bool]($api_settings_obj.ApiConfig.PSobject.Properties.name -match "DeviceId")) {
        $Private:api_settings_obj.ApiConfig | Add-Member -MemberType NoteProperty -Name "DeviceId" -Value -1;
		If ($Debug) {
			Write-Log2 -Path "$logLocation" -Message "add DeviceId as property" -Level Info
		}
    }
	#If OrganizationGroupName property doesn't exist in the api.config file then add it
	If(![bool]($api_settings_obj.ApiConfig.PSobject.Properties.name -match "OrganizationGroupName")) {
        $Private:api_settings_obj.ApiConfig | Add-Member -MemberType NoteProperty -Name "OrganizationGroupName" -Value -1;
		If ($Debug) {
			Write-Log2 -Path "$logLocation" -Message "add OrganizationGroupName as property" -Level Info
		}
    }

    return $api_settings_obj;
}

#OLD FUNCTION USE GET-NEWDEVICEID
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
    param([string]$Endpoint, [string]$Method="GET", $ApiVersion=1, $Data, [bool]$Debug, [string]$SSLThumbPrint, [string]$Server, [string]$OrganizationGroupId, [string]$API_Key, [string]$Auth, [string]$DeviceId)
	
    #$Private:api_settings_obj = Get-AWAPIConfiguration; #done once in main program
	#$SSLThumbprint = $Private:api_settings_obj.ApiConfig.SSLThumbprint;
	If($Debug) {
		Write-Log2 -Path "$logLocation" -Message "Entered Invoke-SecureWebRequest with Server/Endpoint: $Server/$Endpoint and $SSLThumbprint and $DeviceId" -Level Info
    }
	$Endpoint = $Endpoint.Replace("{DeviceId}",$DeviceId).Replace("{OrganizationGroupId}",$OrganizationGroupId);

    Try
    {
        # Create web request
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		$WebRequest = [System.Net.WebRequest]::Create("$Server/$Endpoint")
		If($Debug) {
			Write-Log2 -Path "$logLocation" -Message "webrequest create: $Server/$Endpoint" -Level Info
        }
		$WebRequest.Method = $Method;

        #Setting Private Headers
        #$WebRequest.Headers.Add("aw-tenant-code",$Private:api_settings_obj.ApiConfig.ApiKey);
        #$WebRequest.Headers.Add("Authorization",$Private:api_settings_obj.ApiConfig.ApiAuth);
        $WebRequest.Headers.Add("aw-tenant-code",$API_Key);
        $WebRequest.Headers.Add("Authorization",$Auth);
		
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
            #$ThumbPrint = $SSLThumbprint;
			
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$args[1]
            #Write-Log2 -Path "$logLocation" -Message "certificate: $certificate" -Level Info
            If ($certificate -eq $null)
            {
                Write-Log2 -Path "$logLocation" -Message "no cert" -Level WARN
				return $false
            }
 
            #If (($certificate.Thumbprint -eq $ThumbPrint) -and ($certificate.SubjectName.Name -ne $certificate.IssuerName.Name))
			If ($certificate.Thumbprint -eq $SSLThumbprint) #-and ($certificate.SubjectName.Name -ne $certificate.IssuerName.Name))
            {
                If($Debug) {
					Write-Log2 -Path "$logLocation" -Message "Certificate is good" -Level Info
				}
				return $true
            }
			If($Debug) {
				Write-Log2 -Path "$logLocation" -Message "Certificate is no good" -Level WARN
			}
            return $false
        }      
        # Get response stream
        $Response = $webrequest.GetResponse();
        $ResponseStream = $webrequest.GetResponse().GetResponseStream()

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
    param([string]$Endpoint, $Method="Get", $ApiVersion=1, $Data, [bool]$Debug, [string]$SSLThumbPrint, [string]$Server, [string]$OrganizationGroupId, [string]$API_Key, [string]$Auth, [string]$DeviceId)
    
    #$Private:api_settings_obj = Get-AWAPIConfiguration;
	Write-Log2 -Path "$logLocation" -Message "Entered Invoke-PrivateWebRequest with Global:Server/Endpoint: $Global:Server/$Endpoint" -Level Info
    $Endpoint = $Endpoint.Replace("{DeviceId}",$DeviceId).Replace("{OrganizationGroupId}",$OrganizationGroupId);
    $WebRequest = $null;
    Try {
		#NOT SURE IF HEADERv1 WILL WORK AS THAT OBJECT DOESN'T EXIST
	    $WebRequest = Invoke-WebRequest -Uri ("$Global:Server/$Endpoint") -Method $Method -Headers $Private:api_settings_obj."HeadersV$ApiVersion" -Body $Data -UseBasicParsing;
		Write-Log2 -message "WebRequest: $WebRequest" WARN
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
	param([string]$Method="GET", $ApiVersion=1, $Data, [bool]$Debug, [string]$SSLThumbPrint, [string]$Server, [string]$OrganizationGroupId, [string]$API_Key, [string]$Auth)

    $serialSearch = wmic bios get serialnumber;
    $serialnumber = $serialSearch[2];
    $serialnumber = $serialnumber.Trim();
	$serialEncoded = [System.Web.HttpUtility]::UrlEncode($serialnumber);
    $deviceSearchEndpoint = "api/mdm/devices?searchBy=Serialnumber&id=$serialEncoded";
	If($Debug){
		Write-Log2 -Path "$logLocation" -Message "Entered Get-NewDeviceId" -Level Info
		Write-Log2 -Path "$logLocation" -Message "-----------------------" -Level Info
		Write-Log2 -Path "$logLocation" -Message "serialnumber: $serialnumber" -Level Info
		Write-Log2 -Path "$logLocation" -Message "SSLThumbprint: $SSLThumbprint" -Level Info
	}
	
    If($SSLThumbprint){      
		$WebResponse = Invoke-SecureWebRequest -Endpoint $deviceSearchEndpoint -Method $Method -ApiVersion 1 -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -API_Key $API_Key -Auth $Auth
    } Else {
		$WebResponse = Invoke-PrivateWebRequest -Endpoint $deviceSearchEndpoint -Method $Method -ApiVersion 1 -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -API_Key $API_Key -Auth $Auth
    }
	
	If($Debug){
		Write-Log2 -Path "$logLocation" -Message "Search for Device: $WebResponse.Content" -Level Info
	}
		
    If($WebResponse.StatusCode -lt 300){
        If($WebResponse.Content){
            $device_json = ConvertFrom-Json($WebResponse.Content); 
			If($Debug){
				Write-Log2 -Path "$logLocation" -Message "device_json: $device_json" -Level Info
			}
        }
    }
    
	If($device_json.Id){
        #$DeviceId = $device_json.Id.Value;
        If ($device_json.EnrollmentStatus -ne "Enrolled"){
            return "Unenrolled";
        }
		return $device_json
    }
    return "Unenrolled";
}

function Invoke-AWApiCommand{
    param([string]$Endpoint, [string]$Method="GET", $ApiVersion=1, $Data, [bool]$Debug, [string]$SSLThumbPrint, [string]$Server, [string]$OrganizationGroupId, [string]$API_Key, [string]$Auth, [string]$DeviceId)
    #$loglocation = "C:\ProgramData\Airwatch\Logs\test.log"
	If($Debug){
		Write-Log2 -Path "$logLocation" -Message "Entered Invoke-AWApiCommand with endpoint: $Endpoint" -Level Info
		Write-Log2 -Path "$logLocation" -Message "---------------------------------------------------------------------------" -Level Info
	}
    #Return Object set
    $ReturnObjectSet = @();

	If($Private:SSLThumbprint){
		#$Private:api_settings_obj = $null;
		$WebRequest = Invoke-SecureWebRequest -Endpoint $Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth -DeviceId $DeviceId
		#$Mode = 1;
	} Else{
		#$Private:api_settings_obj = $null;
		$WebRequest = Invoke-PrivateWebRequest -Endpoint $Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth -DeviceId $DeviceId
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
								Write-Log2 -Path $logLocation -Message $Page_Endpoint;
							} Else{
								$Page_Endpoint = $Endpoint + "?page=" + ($ReturnObj.Page + 1).ToString();
								Write-Log2 -Path $logLocation -Message $Page_Endpoint;
							}

							#If($Mode -eq 1){
							If($Private:SSLThumbprint){
								$WebRequest = Invoke-SecureWebRequest -Endpoint $Page_Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth -DeviceId $DeviceId
							} Else {
								$WebRequest = Invoke-PrivateWebRequest -Endpoint $Page_Endpoint -Method $Method -ApiVersion $ApiVersion -Data $Data -Debug $Debug -SSLThumbPrint $SSLThumbPrint -Server $Server -OrganizationGroupId $OrganizationGroupId -API_Key $API_Key -Auth $Auth -DeviceId $DeviceId
							}
							if($WebRequest.StatusCode -eq 200){
								 $ReturnObj += (ConvertFrom-Json($WebRequest.Content)); 
							}
						}
					}
				}
			}
			If($Debug){
				Write-Log2 -Path $logLocation -Message "ReturnObj: $ReturnObj";
			}
			return $ReturnObj;
	
        } Else {
			return $WebRequest.Content;
        }
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        return (New-Object -TypeName PSCustomObject -Property @{"Error"="$ErrorMessage"});
    }
}

Export-ModuleMember -Function Get-AWAPIConfiguration, Invoke-SecureWebRequest, Invoke-PrivateWebRequest, Get-NewDeviceId, Invoke-AWApiCommand
