Process {
    # Functions
    function Test-AzureADDeviceRegistration {
        Process {
            $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
            if (Test-Path -Path $AzureADJoinInfoRegistryKeyPath) {
                return $true
            }
            else {
                return $false
            }
        }
    }

    function Get-AzureADDeviceID {
        Process {
            # Define Cloud Domain Join information registry path
            $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

            # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
            $AzureADJoinInfoKey = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
            if ($AzureADJoinInfoKey -ne $null) {
                # Match key data against GUID regex
                if ([guid]::TryParse($AzureADJoinInfoKey, $([ref][guid]::Empty))) {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoKey)" }
                }
                else {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoKey }
                }

                # Retrieve the machine certificate based on thumbprint from registry key
                if ($AzureADJoinCertificate -ne $null) {
                    # Determine the device identifier from the subject name
                    $AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""

                    # Write event log entry with DeviceId
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 51 -Message "CloudLAPS: Azure AD device identifier: $($AzureADDeviceID)"

                    # Handle return value
                    return $AzureADDeviceID
                }
            }
        }
    }

    function Get-AzureADRegistrationCertificateThumbprint {
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoKey = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
         # Retrieve the machine certificate based on thumbprint from registry key or Certificate (CloudPC)
        if ($AzureADJoinInfoKey -ne $null) {
            # Match key data against GUID regex for CloudPC Support
            if ([guid]::TryParse($AzureADJoinInfoKey, $([ref][guid]::Empty))) {
                #This is for CloudPC
                $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoKey)" }
                $AzureADJoinInfoThumbprint = $AzureADJoinCertificate.Thumbprint
            }
            else {
                # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid (non-CloudPC)
                $AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
            }
        }
        # Handle return value
        return $AzureADJoinInfoThumbprint
    }
}

    function New-RSACertificateSignature {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the content string to be signed.")]
            [ValidateNotNullOrEmpty()]
            [string]$Content,

            [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
            [ValidateNotNullOrEmpty()]
            [string]$Thumbprint
        )
        Process {
            # Determine the certificate based on thumbprint input
            $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $CertificateThumbprint }
            if ($Certificate -ne $null) {
                if ($Certificate.HasPrivateKey -eq $true) {
                    # Read the RSA private key
                    $RSAPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)

                    if ($RSAPrivateKey -ne $null) {
                        if ($RSAPrivateKey -is [System.Security.Cryptography.RSACng]) {
                            # Construct a new SHA256Managed object to be used when computing the hash
                            $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

                            # Construct new UTF8 unicode encoding object
                            $UnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8

                            # Convert content to byte array
                            [byte[]]$EncodedContentData = $UnicodeEncoding.GetBytes($Content)

                            # Compute the hash
                            [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($EncodedContentData)

                            # Create signed signature with computed hash
                            [byte[]]$SignatureSigned = $RSAPrivateKey.SignHash($ComputedHash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

                            # Convert signature to Base64 string
                            $SignatureString = [System.Convert]::ToBase64String($SignatureSigned)

                            # Handle return value
                            return $SignatureString
                        }
                    }
                }
            }
        }
    }

    function Get-PublicKeyBytesEncodedString {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
            [ValidateNotNullOrEmpty()]
            [string]$Thumbprint
        )
        Process {
            # Determine the certificate based on thumbprint input
            $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $Thumbprint }
            if ($Certificate -ne $null) {
                # Get the public key bytes
                [byte[]]$PublicKeyBytes = $Certificate.GetPublicKey()

                # Handle return value
                return [System.Convert]::ToBase64String($PublicKeyBytes)
            }
        }
    }

    function Get-ComputerSystemType {
        Process {
            # Check if computer system type is virtual
            $ComputerSystemModel = Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty "Model"
            if ($ComputerSystemModel -in @("Virtual Machine", "VMware Virtual Platform", "VirtualBox", "HVM domU", "KVM", "VMWare7,1", "Google Compute Engine")) {
                $ComputerSystemType = "VM"
            }
            else {
                $ComputerSystemType = "NonVM"
            }

            # Handle return value
            return $ComputerSystemType
        }
    }

    # Define the local administrator user name
    $LocalAdministratorName = "localAdmin"

    # Construct the required URI for the Azure Function URL
    $SetSecretURI = "https://oshrcazclouldlapsfunction.azurewebsites.net/api/SetSecret?code=paGq2cxvyjdy2VJ0wuJa8nEbiiFrHQbJ2BuIQ9BoyNBkAzFuAS-ohA=="
    $SendClientEventURI = "https://oshrcazclouldlapsfunction.azurewebsites.net/api/SendClientEvent?code=atu79Wjgr1eJNrfY_4OY6XqxwGJIqWRDP0DyQtEsG-rmAzFu17lG8w=="

    # Control whether client-side events should be sent to Log Analytics workspace
    # Set to $true to enable this feature
    $SendClientEvent = $true

    # Define event log variables
    $EventLogName = "CloudLAPS-Client"
    $EventLogSource = "CloudLAPS-Client"

    # Validate that device is either Azure AD joined or Hybrid Azure AD joined
    if (Test-AzureADDeviceRegistration -eq $true) {
        # Intiate logging
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 10 -Message "CloudLAPS: Local administrator account password rotation started"

        # Retrieve variables required to build request header
        $SerialNumber = Get-WmiObject -Class "Win32_BIOS" | Select-Object -ExpandProperty "SerialNumber"
        $ComputerSystemType = Get-ComputerSystemType
        $AzureADDeviceID = Get-AzureADDeviceID
        $CertificateThumbprint = Get-AzureADRegistrationCertificateThumbprint
        $Signature = New-RSACertificateSignature -Content $AzureADDeviceID -Thumbprint $CertificateThumbprint
        $PublicKeyBytesEncoded = Get-PublicKeyBytesEncodedString -Thumbprint $CertificateThumbprint

        # Construct SetSecret function request header
        $SetSecretHeaderTable = [ordered]@{
            DeviceName = $env:COMPUTERNAME
            DeviceID = $AzureADDeviceID
            SerialNumber = if (-not([string]::IsNullOrEmpty($SerialNumber)) -and ($SerialNumber -ne "System Serial Number")) { $SerialNumber } else { $env:COMPUTERNAME } # fall back to computer name if serial number is not present or equals "System Serial Number"
            Type = $ComputerSystemType
            Signature = $Signature
            Thumbprint = $CertificateThumbprint
            PublicKey = $PublicKeyBytesEncoded
            ContentType = "Local Administrator"
            UserName = $LocalAdministratorName
            SecretUpdateOverride = $false
        }

        # Construct SendClientEvent request header
        $SendClientEventHeaderTable = [ordered]@{
            DeviceName = $env:COMPUTERNAME
            DeviceID = $AzureADDeviceID
            SerialNumber = if (-not([string]::IsNullOrEmpty($SerialNumber)) -and ($SerialNumber -ne "System Serial Number")) { $SerialNumber } else { $env:COMPUTERNAME } # fall back to computer name if serial number is not present or equals "System Serial Number"
            Signature = $Signature
            Thumbprint = $CertificateThumbprint
            PublicKey = $PublicKeyBytesEncoded
            PasswordRotationResult = ""
            DateTimeUtc = (Get-Date).ToUniversalTime().ToString()
            ClientEventMessage = ""
        }

        # Initiate exit code variable with default value if not errors are caught
        $ExitCode = 0

        # Initiate extended output variable
        $ExtendedOutput = [string]::Empty

        # Use TLS 1.2 connection when calling Azure Function
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        try {
            # Check if existing local administrator user account exists
            $LocalAdministratorAccount = Get-LocalUser -Name $LocalAdministratorName -ErrorAction SilentlyContinue

            # Amend header table if local administrator account doesn't exist, enforce password creation for devices that were previously provisioned, but have been re-provisioned
            if ($null -eq $LocalAdministratorAccount) {
                $SetSecretHeaderTable["SecretUpdateOverride"] = $true
            }

            # Call Azure Function SetSecret to store new secret in Key Vault for current computer and have the randomly generated password returned
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 11 -Message "CloudLAPS: Calling Azure Function API for password generation and secret update"
            $APIResponse = Invoke-RestMethod -Method "POST" -Uri $SetSecretURI -Body ($SetSecretHeaderTable | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop

            if ([string]::IsNullOrEmpty($APIResponse)) {
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 13 -Message "CloudLAPS: Retrieved an empty response from Azure Function URL"; $ExitCode = 1
            }
            else {
                # Convert password returned from Azure Function API call to secure string
                $SecurePassword = ConvertTo-SecureString -String $APIResponse -AsPlainText -Force

                if ($null -eq $LocalAdministratorAccount) {
                    # Create local administrator account
                    try {
                        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 20 -Message "CloudLAPS: Local administrator account does not exist, attempt to create it"
                        New-LocalUser -Name $LocalAdministratorName -Password $SecurePassword -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword -ErrorAction Stop

                        try {
                            # Add to local built-in security groups: Administrators (S-1-5-32-544)
                            foreach ($Group in @("S-1-5-32-544")) {
                                $GroupName = Get-LocalGroup -SID $Group | Select-Object -ExpandProperty "Name"
                                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 22 -Message "CloudLAPS: Adding local administrator account to security group '$($GroupName)'"
                                Add-LocalGroupMember -SID $Group -Member $LocalAdministratorName -ErrorAction Stop
                            }

                            # Handle output for extended details in MEM portal
                            $ExtendedOutput = "AdminAccountCreated"
                        }
                        catch [System.Exception] {
                            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 23 -Message "CloudLAPS: Failed to add '$($LocalAdministratorName)' user account as a member of local '$($GroupName)' group. Error message: $($PSItem.Exception.Message)"; $ExitCode = 1
                        }
                    }
                    catch [System.Exception] {
                        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 21 -Message "CloudLAPS: Failed to create new '$($LocalAdministratorName)' local user account. Error message: $($PSItem.Exception.Message)"; $ExitCode = 1
                    }
                }
                else {
                    # Local administrator account already exists, reset password
                    try {
                        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 30 -Message "CloudLAPS: Local administrator account exists, updating password"

                        # Determine if changes are being made to the built-in local administrator account, if so don't attempt to set properties for password changes
                        if ($LocalAdministratorAccount.SID -match "S-1-5-21-.*-500") {
                            Set-LocalUser -Name $LocalAdministratorName -Password $SecurePassword -PasswordNeverExpires $true -ErrorAction Stop
                        }
                        else {
                            Set-LocalUser -Name $LocalAdministratorName -Password $SecurePassword -PasswordNeverExpires $true -UserMayChangePassword $false -ErrorAction Stop
                        }

                        # Handle output for extended details in MEM portal
                        $ExtendedOutput = "PasswordRotated"
                    }
                    catch [System.Exception] {
                        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 31 -Message "CloudLAPS: Failed to rotate password for '$($LocalAdministratorName)' local user account. Error message: $($PSItem.Exception.Message)"; $ExitCode = 1
                    }
                }

                if (($SendClientEvent -eq $true) -and ($Error.Count -eq 0)) {
                    # Amend header table with success parameters before sending client event
                    $SendClientEventHeaderTable["PasswordRotationResult"] = "Success"
                    $SendClientEventHeaderTable["ClientEventMessage"] = "Password rotation completed successfully"

                    try {
                        # Call Azure Functions SendClientEvent API to post client event
                        $APIResponse = Invoke-RestMethod -Method "POST" -Uri $SendClientEventURI -Body ($SendClientEventHeaderTable | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop

                        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 50 -Message "CloudLAPS: Successfully sent client event to API. Message: $($SendClientEventHeaderTable["ClientEventMessage"])"
                    }
                    catch [System.Exception] {
                        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 51 -Message "CloudLAPS: Failed to send client event to API. Error message: $($PSItem.Exception.Message)"; $ExitCode = 1
                    }
                }

                # Final event log entry
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 40 -Message "CloudLAPS: Local administrator account password rotation completed"
            }
        }
        catch [System.Exception] {
            switch ($PSItem.Exception.Response.StatusCode) {
                "Forbidden" {
                    # Handle output for extended details in MEM portal
                    $FailureResult = "NotAllowed"
                    $FailureMessage = "Password rotation not allowed"
                    $ExtendedOutput = $FailureResult

                    # Write to event log and set exit code
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Warning -EventId 14 -Message "CloudLAPS: Forbidden, password was not allowed to be updated"; $ExitCode = 0
                }
                "BadRequest" {
                    # Handle output for extended details in MEM portal
                    $FailureResult = "BadRequest"
                    $FailureMessage = "Password rotation failed with BadRequest"
                    $ExtendedOutput = $FailureResult

                    # Write to event log and set exit code
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 15 -Message "CloudLAPS: BadRequest, failed to update password"; $ExitCode = 1
                }
                "TooManyRequests" {
                    # Handle output for extended details in MEM portal
                    $FailureResult = "TooManyRequests"
                    $FailureMessage = "Password rotation failed with TooManyRequests (throttled)"
                    $ExtendedOutput = $FailureResult

                    # Write to event log and set exit code
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 16 -Message "CloudLAPS: TooManyRequests returned by API, failed to update password"; $ExitCode = 1
                }
                "GatewayTimeout" {
                    # Handle output for extended details in MEM portal
                    $FailureResult = "GatewayTimeout"
                    $FailureMessage = "Password rotation failed with GatewayTimeout"
                    $ExtendedOutput = $FailureResult

                    # Write to event log and set exit code
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 17 -Message "CloudLAPS: GatewayTimeout for API request, failed to update password"; $ExitCode = 1
                }
                default {
                    # Handle output for extended details in MEM portal
                    $FailureResult = "Failed"
                    $FailureMessage = "Password rotation failed with unhandled exception '$($PSItem.Exception.Response.StatusCode)'"
                    $ExtendedOutput = $FailureResult

                    # Write to event log and set exit code
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 12 -Message "CloudLAPS: Call to Azure Function URI failed. Error message: $($PSItem.Exception.Message)"; $ExitCode = 1
                }
            }

            if ($SendClientEvent -eq $true) {
                # Amend header table with success parameters before sending client event
                $SendClientEventHeaderTable["PasswordRotationResult"] = $FailureResult
                $SendClientEventHeaderTable["ClientEventMessage"] = $FailureMessage

                try {
                    # Call Azure Functions SendClientEvent API to post client event
                    $APIResponse = Invoke-RestMethod -Method "POST" -Uri $SendClientEventURI -Body ($SendClientEventHeaderTable | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop

                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 52 -Message "CloudLAPS: Successfully sent client event to API. Message: $($FailureMessage)"
                }
                catch [System.Exception] {
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 53 -Message "CloudLAPS: Failed to send client event to API. Error message: $($PSItem.Exception.Message)"; $ExitCode = 1
                }
            }
        }
    }
    else {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 1 -Message "CloudLAPS: Azure AD device registration failed, device is not Azure AD joined or Hybrid Azure AD joined"; $ExitCode = 1

        # Handle output for extended details in MEM portal
        $ExtendedOutput = "DeviceRegistrationTestFailed"
    }

    # Write output for extended details in MEM portal
    Write-Output -InputObject $ExtendedOutput

    # Handle exit code
    exit $ExitCode
}
