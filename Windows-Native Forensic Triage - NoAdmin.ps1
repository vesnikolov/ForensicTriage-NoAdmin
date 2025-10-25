# ================================================
#  Windows-Native Forensic Triage Script
#  Optimized & Annotated Version
#  Requirements:  No Admin Rights are necessary. The collected data is suitable for iport in Power Bi.
# # ================================================

# -------------------------------
# Setup output environment
# -------------------------------
$outputFolder = "C:\Forensics\Timeline_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
Write-Host "`n[+] Starting forensic data collection..."

# -------------------------------
# Ensure ImportExcel module exists
# -------------------------------
if (-not (Get-Module -ListAvailable ImportExcel)) {
    Write-Host "[*] Installing ImportExcel module..."
    Install-Module ImportExcel -Scope CurrentUser -Force
}

# -------------------------------
# Initialize data structure to store timeline entries
# Each key (source) holds an array of event objects
# -------------------------------
$timelineSources = @{}

# -------------------------------
# Function: Add-Entry
# Adds an event entry to the in-memory timeline table
# -------------------------------
function Add-Entry {
    param(
        [string]$Source,
        [datetime]$Timestamp,
        [string]$Description,
        [string]$User = ""
    )
    if (-not $Timestamp -or -not $Description) { return }
    if (-not $timelineSources.ContainsKey($Source)) { $timelineSources[$Source] = @() }
    $timelineSources[$Source] += [PSCustomObject]@{
        Timestamp   = $Timestamp
        Source      = $Source
        Description = $Description
        User        = $User
    }
}

# -------------------------------
# Function: Save-CSV
# Exports each source’s collected entries to CSV
# -------------------------------
function Save-CSV {
    param([string]$Source)
    $path = Join-Path $outputFolder "$Source.csv"
    $timelineSources[$Source] | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Saved $Source to CSV: $path"
}

# -------------------------------
# Function: Get-UserName
# Converts a SecurityIdentifier (SID) to NT Account string
# -------------------------------
function Get-UserName {
    param($sid)
    try {
        if ($sid -is [System.Security.Principal.SecurityIdentifier]) {
            return $sid.Translate([System.Security.Principal.NTAccount]).Value
        }
    } catch { }
    return ""
}

# -------------------------------
# Function: Try-Action
# Generic wrapper for try/catch to reduce boilerplate
# -------------------------------
function Invoke-Action {
    param(
        [scriptblock]$Action,
        [string]$Context
    )
    try { & $Action }
    catch { Write-Host "[!] $Context failed: $($_.Exception.Message)" }
}

# ==========================================================
#  DATA COLLECTION SECTIONS
# ==========================================================

# -------------------------------
# Collect Windows Event Logs (System, Security, Application)
# Collects 500 events per log for speed
# -------------------------------
Invoke-Action {
    $logs = "System","Security","Application"
    foreach ($log in $logs) {
        Get-WinEvent -LogName $log -MaxEvents 500 | ForEach-Object {
            Add-Entry -Source "EventLog_$log" -Timestamp $_.TimeCreated `
                      -Description $_.Message -User (Get-UserName $_.UserId)
        }
        Write-Host "[+] Event log $log collected"
    }
} "Event Logs"

# -------------------------------
# Collect Prefetch file metadata (program execution traces)
# -------------------------------
Invoke-Action {
    Get-ChildItem "$env:SystemRoot\Prefetch" -Filter *.pf -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Entry -Source "Prefetch" -Timestamp $_.LastWriteTime -Description $_.Name
    }
    Write-Host "[+] Prefetch metadata collected"
} "Prefetch Files"

# -------------------------------
# Collect USB device connection history from registry
# -------------------------------
Invoke-Action {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -ErrorAction SilentlyContinue | ForEach-Object {
        $time = $_.GetValue("InstallDate")
        if (-not $time) { $time = Get-Date } # fallback timestamp
        Add-Entry -Source "USBDevices" -Timestamp $time -Description $_.Name
    }
    Write-Host "[+] USB device history collected"
} "USB Devices"

# -------------------------------
# Collect Scheduled Tasks information
# (Uses StartBoundary timestamps if available)
# -------------------------------
Invoke-Action {
    Get-ScheduledTask | ForEach-Object {
        if ($_.Triggers -and $_.Triggers[0].StartBoundary) {
            $start = [datetime]$_.Triggers[0].StartBoundary
            Add-Entry -Source "ScheduledTasks" -Timestamp $start `
                      -Description $_.TaskName -User $_.Principal.UserId
        }
    }
    Write-Host "[+] Scheduled tasks collected"
} "Scheduled Tasks"

# -------------------------------
# Collect Installed Software (fast registry-based method)
# -------------------------------
Invoke-Action {
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $now = Get-Date
    foreach ($key in $uninstallKeys) {
        Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {
            $app = Get-ItemProperty $_.PSPath
            if ($app.DisplayName) {
                Add-Entry -Source "InstalledSoftware" -Timestamp $now -Description $app.DisplayName
            }
        }
    }
    Write-Host "[+] Installed software collected (registry method)"
} "Installed Software"

# -------------------------------
# Collect PowerShell command history
# -------------------------------
Invoke-Action {
    $psHist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHist) {
        Get-Content $psHist | ForEach-Object {
            Add-Entry -Source "PowerShellHistory" -Timestamp (Get-Date) `
                      -Description $_ -User $env:USERNAME
        }
        Write-Host "[+] PowerShell history collected"
    } else {
        Write-Host "[!] PowerShell history file not found."
    }
} "PowerShell History"

# ==========================================================
#  OUTPUT & POST-PROCESSING
# ==========================================================

# -------------------------------
# Export all data sources to individual CSVs
# -------------------------------
$timelineSources.Keys | ForEach-Object { Save-CSV $_ }

# -------------------------------
# Combine all CSVs into one Excel workbook
# Each worksheet = data source
# -------------------------------
$excelPath = Join-Path $outputFolder "Timeline_Combined.xlsx"
Invoke-Action {
    foreach ($source in $timelineSources.Keys) {
        $csv = Join-Path $outputFolder "$source.csv"
        Import-Csv $csv | Export-Excel -Path $excelPath -WorksheetName $source -AutoSize -Append
    }
    Write-Host "`n[+] Combined Excel file created: $excelPath"
} "Excel Export"

# -------------------------------
# Optional: Create Master Timeline (chronologically sorted)
# -------------------------------
Invoke-Action {
    $allEntries = @()
    foreach ($source in $timelineSources.Keys) {
        $allEntries += $timelineSources[$source]
    }
    $allEntries = $allEntries | Sort-Object Timestamp

    # Export combined timeline directly to Excel worksheet
    $allEntries | Export-Excel -Path $excelPath -WorksheetName "MasterTimeline" -AutoSize -Append

    Write-Host "[+] Master Timeline worksheet added"
} "Master Timeline"

# -------------------------------
# Compute SHA256 hashes of all CSVs for integrity
# -------------------------------
Invoke-Action {
    $hashFile = Join-Path $outputFolder "File_Hashes.csv"
    $hashes = Get-ChildItem $outputFolder -Filter *.csv | ForEach-Object {
        $hash = Get-FileHash $_.FullName -Algorithm SHA256
        [PSCustomObject]@{ File = $_.Name; SHA256 = $hash.Hash }
    }
    $hashes | Export-Csv $hashFile -NoTypeInformation
    Write-Host "[+] File integrity hashes saved: $hashFile"
} "File Hashing"

# -------------------------------
# Capture basic system information snapshot
# -------------------------------
Invoke-Action {
    Get-ComputerInfo |
        Select-Object CsName, OsName, OsVersion, OsBuildNumber, WindowsProductName, CsManufacturer, CsModel |
        Export-Csv (Join-Path $outputFolder "SystemInfo.csv") -NoTypeInformation
    Write-Host "[+] System information captured"
} "System Info"

# -------------------------------
# Optionally, archive the results for transport
# -------------------------------
Invoke-Action {
    Compress-Archive -Path $outputFolder -DestinationPath "${outputFolder}.zip" -Force
    Write-Host "[+] Output folder archived: ${outputFolder}.zip"
} "Archiving Results"

# -------------------------------
# Wrap up and final output
# -------------------------------
Write-Host "`n[+] Timeline data collection complete."
Write-Host "[+] All files saved to: $outputFolder"