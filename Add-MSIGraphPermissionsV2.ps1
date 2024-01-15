#Requires -Modules Microsoft.Graph
# Install the module. (You need admin on the machine.)
# Install-Module Microsoft.Graph

# Set Static Variables
$TenantID="332f08e4-4a3b-4f06-a065-c4f6f8f8474d"
$ServicePrincipalAppDisplayNames = @("OSHRCAzCloudLAPSPortal") #"OSHRCAzIntuneEi", "OSHRCAzIntuneLogCollector"#)
$GraphAPIAppName = "Microsoft Graph"
$ApiServicePrincipalFilter = "displayName eq '$($GraphAPIAppName)'"

# Scopes needed for the managed identity (Add other scopes if needed)
$Scopes = @(
    "Device.Read.All",
    "DeviceLocalCredential.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementRBAC.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "Directory.Read.All",
    "ProgramControl.Read.All",
    "Reports.Read.All",
    "Application.Read.All",
    "AuditLog.Read.All",
    "offline_access",
    "Organization.Read.All",
    "Synchronization.Read.All"
)

# Connect to MG Graph - scopes must be consented the first time you run this. 
# Connect with Global Administrator
Select-MgProfile -Name "beta"
Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.ReadWrite.All"  -TenantId $TenantID -UseDeviceAuthentication

foreach ($ServicePrincipalAppDisplayName in $ServicePrincipalAppDisplayNames) {
    # Define dynamic variables
    $ServicePrincipalFilter = "displayName eq '$($ServicePrincipalAppDisplayName)'"

    # Get the service principal for your managed identity.
    $ServicePrincipal = Get-MgServicePrincipal -Filter $ServicePrincipalFilter

    # Get the service principal for Microsoft Graph. 
    # Result should be AppId 00000003-0000-0000-c000-000000000000
    $ApiServicePrincipal = Get-MgServicePrincipal -Filter "$ApiServicePrincipalFilter"

    # Apply permissions
    foreach ($Scope in $Scopes) {
        Write-Host "`nGetting App Role '$Scope'"
        $AppRole = $ApiServicePrincipal.AppRoles | Where-Object {$_.Value -eq $Scope -and $_.AllowedMemberTypes -contains "Application"}
        if ($null -eq $AppRole) { Write-Error "Could not find the specified App Role on the Api Service Principal"; continue; }
        if ($AppRole -is [array]) { Write-Error "Multiple App Roles found that match the request"; continue; }
        Write-Host "Found App Role, Id '$($AppRole.Id)'"

        $ExistingRoleAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id | Where-Object { $_.AppRoleId -eq $AppRole.Id }
        if ($null -eq $existingRoleAssignment) {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -PrincipalId $ServicePrincipal.Id -ResourceId $ApiServicePrincipal.Id -AppRoleId $AppRole.Id
        } else {
            Write-Host "App Role has already been assigned, skipping"
        }
    }
}
