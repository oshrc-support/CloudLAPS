Process {
    # Create new event log if it doesn't already exist
    $EventLogName = "CloudLAPS-Client"
    $EventLogSource = "CloudLAPS-Client"
    $CloudLAPSEventLog = Get-WinEvent -LogName $EventLogName -ErrorAction SilentlyContinue
    if ($null -eq $CloudLAPSEventLog) {
        try {
            New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Failed to create new event log. Error message: $($_.Exception.Message)"
        }
    }

    # Trigger remediation script
    exit 1
}