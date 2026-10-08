# Requires: Run as Administrator
# Purpose: Audit SMB shares for local path, size, file count, recent active users, owner details, NTFS permissions
#          Export to CSV files, and create separate report for folders with disabled inheritance
# Output: Saves to $env:USERPROFILE\Downloads\temp\

$ErrorActionPreference = "Stop"

# Guard rails: the script relies on Windows SMB/NTFS cmdlets and admin rights.
if (-not $IsWindows) {
    throw "This script must run on Windows because it uses Get-SmbShare, Get-Acl, and Get-WinEvent, which are not available on this platform."
}

$requiredCommands = @('Get-SmbShare', 'Get-Acl', 'Get-ChildItem', 'Export-Csv')
foreach ($cmd in $requiredCommands) {
    if (-not (Get-Command -Name $cmd -ErrorAction SilentlyContinue)) {
        throw "Required command '$cmd' was not found. Run this script on a Windows machine with the SMB/NTFS cmdlets available."
    }
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator to enumerate SMB shares and read NTFS permissions."
}

# --------------------------
# Configuration
# --------------------------
$username = $env:USERNAME
$OutFolder = "$env:USERPROFILE\Downloads\temp"
$CsvPath_Main = Join-Path $OutFolder "SharedFoldersAudit_Main.csv"
$CsvPath_NoInheritance = Join-Path $OutFolder "SharedFoldersAudit_NoInheritance.csv"
$CsvPath_Permissions = Join-Path $OutFolder "SharedFoldersAudit_Permissions_Detailed.csv"

# --------------------------
# Helper functions
# --------------------------
function Get-ShareInfo {
    param([string]$ShareName)

    $share = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
    if (-not $share) {
        return $null
    }

    return [PSCustomObject]@{
        ShareName = $share.Name
        Path      = $share.Path
        Description = $share.Description
        FolderEnumerationMode = $share.FolderEnumerationMode
        EncryptData = $share.EncryptData
        Cache = $share.CachingMode
        Scoped = $share.IsScoped
    }
}

function Get-FolderStats {
    param([string]$Path)

    $stats = [ordered]@{
        TotalSizeGB = 0
        FileCount   = 0
        FolderCount = 0
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]$stats
    }

    try {
        $items = Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue
        if ($null -eq $items) {
            return [PSCustomObject]$stats
        }

        $totalSize = 0
        $fileCount = 0
        $folderCount = 0

        foreach ($item in $items) {
            if ($item.PSIsContainer) {
                $folderCount++
            } else {
                $fileCount++
                $totalSize += $item.Length
            }
        }

        $stats.TotalSizeGB = [math]::Round(($totalSize / 1GB), 4)
        $stats.FileCount   = $fileCount
        $stats.FolderCount = $folderCount
        return [PSCustomObject]$stats
    }
    catch {
        return [PSCustomObject]$stats
    }
}

function Get-ShareOwnerDetails {
    param([string]$Path)

    $owner = $null
    try {
        $owner = (Get-Acl -Path $Path).Owner
    }
    catch {
        $owner = "Unknown"
    }

    return $owner
}

function Get-NTFSAccess {
    param([string]$Path)

    try {
        $acl = Get-Acl -Path $Path
        $rules = $acl.Access | ForEach-Object {
            [PSCustomObject]@{
                Identity = $_.IdentityReference.Value
                Access   = $_.FileSystemRights.ToString()
                Type     = $_.AccessControlType.ToString()
                Inherited = $_.IsInherited
            }
        }
        return $rules
    }
    catch {
        return @(
            [PSCustomObject]@{
                Identity = "ERROR"
                Access   = $_.Exception.Message
                Type     = "ERROR"
                Inherited = $false
            }
        )
    }
}

function Get-ShareActiveUsers {
    param([string]$Path)

    $activeUsers = @()

    try {
        # Check NTFS access and parse identity references (users/groups)
        $acl = Get-Acl -Path $Path
        foreach ($accessRule in $acl.Access) {
            $identity = $accessRule.IdentityReference.Value
            if ($identity -notmatch "^S-1-") {
                $activeUsers += $identity
            }
        }
    }
    catch {
        $activeUsers = @("Unknown")
    }

    # For true 90-day activity, check Security Event Logs
    try {
        $cutoff = (Get-Date).AddDays(-90)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4663  # File access audit
            StartTime = $cutoff
        } -ErrorAction SilentlyContinue | Where-Object { $_.Properties[8].Value -like "*$([regex]::Escape($Path))*" }

        if ($events) {
            $eventUsers = $events | ForEach-Object {
                $_.Properties[1].Value  # SubjectUserName
            } | Sort-Object -Unique
            $activeUsers += $eventUsers
        }
    }
    catch {
        # Security log access might be restricted or not available
    }

    return ($activeUsers | Sort-Object -Unique)
}

function Check-InheritanceDisabled {
    param([string]$Path)

    try {
        $acl = Get-Acl -Path $Path
        # If inheritance is disabled, AreAccessRulesProtected = $true
        return $acl.AreAccessRulesProtected
    }
    catch {
        return $false
    }
}

function Get-FoldersWithNoInheritance {
    param([string]$Path)

    $noInheritanceFolders = @()

    if (-not (Test-Path -LiteralPath $Path)) {
        return $noInheritanceFolders
    }

    try {
        $folders = Get-ChildItem -LiteralPath $Path -Directory -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($folder in $folders) {
            if (Check-InheritanceDisabled -Path $folder.FullName) {
                $noInheritanceFolders += $folder.FullName
            }
        }
    }
    catch {
        # Suppress errors during recursion
    }

    return $noInheritanceFolders
}

# --------------------------
# Create output folder
# --------------------------
if (-not (Test-Path -LiteralPath $OutFolder)) {
    New-Item -ItemType Directory -Path $OutFolder -Force | Out-Null
    Write-Host "Created output folder: $OutFolder" -ForegroundColor Green
}

# --------------------------
# Gather shares
# --------------------------
Write-Host "Scanning shared folders..." -ForegroundColor Cyan
try {
    $allShares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Path -and $_.Path -ne "" })
}
catch {
    Write-Warning "Unable to enumerate SMB shares. Verify the machine is Windows and the SMB Share cmdlets are available. $($_.Exception.Message)"
    $allShares = @()
}

$results = @()
$noInheritanceResults = @()
$permissionsDetails = @()

foreach ($share in $allShares) {
    $shareName = $share.Name
    $localPath = $share.Path

    Write-Host "Processing: $shareName -> $localPath" -ForegroundColor Yellow

    $stats = Get-FolderStats -Path $localPath
    $owner = Get-ShareOwnerDetails -Path $localPath
    $activeUsers = Get-ShareActiveUsers -Path $localPath
    $inheritanceDisabled = Check-InheritanceDisabled -Path $localPath

    $ntfsAccess = Get-NTFSAccess -Path $localPath
    $ntfsPermissionsText = ($ntfsAccess | ForEach-Object {
        "{0}; {1}; {2}; Inherited={3}" -f $_.Identity, $_.Access, $_.Type, $_.Inherited
    }) -join " | "

    # Main results object
    $mainResult = [PSCustomObject]@{
        ShareName               = $shareName
        LocalPath               = $localPath
        Description             = $share.Description
        TotalSizeGB             = $stats.TotalSizeGB
        FileCount               = $stats.FileCount
        FolderCount             = $stats.FolderCount
        Owner                   = $owner
        InheritanceDisabled     = $inheritanceDisabled
        ActiveUsers90d          = ($activeUsers -join "; ")
        NTFSPermissions         = $ntfsPermissionsText
    }
    $results += $mainResult

    # Detailed permissions - one row per permission
    foreach ($acl in $ntfsAccess) {
        $permissionsDetails += [PSCustomObject]@{
            ShareName           = $shareName
            LocalPath           = $localPath
            Identity            = $acl.Identity
            FileSystemRights    = $acl.Access
            AccessControlType   = $acl.Type
            IsInherited         = $acl.Inherited
            ShareInheritanceDisabled = $inheritanceDisabled
        }
    }

    # Check for folders with disabled inheritance
    if ($inheritanceDisabled) {
        $noInheritanceResults += $mainResult
    }

    # Get subfolders with no inheritance
    $subFoldersNoInheritance = Get-FoldersWithNoInheritance -Path $localPath
    foreach ($folder in $subFoldersNoInheritance) {
        $folderStats = Get-FolderStats -Path $folder
        $folderOwner = Get-ShareOwnerDetails -Path $folder
        $folderPermissions = Get-NTFSAccess -Path $folder
        $folderPermissionsText = ($folderPermissions | ForEach-Object {
            "{0}; {1}; {2}; Inherited={3}" -f $_.Identity, $_.Access, $_.Type, $_.Inherited
        }) -join " | "

        $noInheritanceResults += [PSCustomObject]@{
            ShareName               = $shareName
            LocalPath               = $folder
            Description             = "Subfolder with disabled inheritance"
            TotalSizeGB             = $folderStats.TotalSizeGB
            FileCount               = $folderStats.FileCount
            FolderCount             = $folderStats.FolderCount
            Owner                   = $folderOwner
            InheritanceDisabled     = $true
            ActiveUsers90d          = ""
            NTFSPermissions         = $folderPermissionsText
        }
    }
}

# --------------------------
# Export to CSV files
# --------------------------
Write-Host "Exporting results..." -ForegroundColor Cyan

$emptyMainRow = [PSCustomObject]@{
    ShareName = ""
    LocalPath = ""
    Description = "No SMB shares detected"
    TotalSizeGB = $null
    FileCount = 0
    FolderCount = 0
    Owner = ""
    InheritanceDisabled = $false
    ActiveUsers90d = ""
    NTFSPermissions = ""
}

if ($results.Count -gt 0) {
    $results | Sort-Object ShareName | Export-Csv -Path $CsvPath_Main -NoTypeInformation -Encoding UTF8
}
else {
    @($emptyMainRow) | Export-Csv -Path $CsvPath_Main -NoTypeInformation -Encoding UTF8
}
Write-Host "✓ Main audit report: $CsvPath_Main" -ForegroundColor Green
Write-Host "  Total shares audited: $($results.Count)" -ForegroundColor Green

# Detailed permissions report
if ($permissionsDetails.Count -gt 0) {
    $permissionsDetails | Export-Csv -Path $CsvPath_Permissions -NoTypeInformation -Encoding UTF8
    Write-Host "✓ Detailed permissions report: $CsvPath_Permissions" -ForegroundColor Green
    Write-Host "  Total permission entries: $($permissionsDetails.Count)" -ForegroundColor Green
}
else {
    $emptyPermissionsRow = [PSCustomObject]@{
        ShareName = ""
        LocalPath = ""
        Identity = ""
        FileSystemRights = ""
        AccessControlType = ""
        IsInherited = $false
        ShareInheritanceDisabled = $false
    }
    @($emptyPermissionsRow) | Export-Csv -Path $CsvPath_Permissions -NoTypeInformation -Encoding UTF8
    Write-Host "✓ Detailed permissions report: $CsvPath_Permissions" -ForegroundColor Green
    Write-Host "  Total permission entries: 0" -ForegroundColor Green
}

# No inheritance report
if ($noInheritanceResults.Count -gt 0) {
    $noInheritanceResults | Sort-Object LocalPath | Export-Csv -Path $CsvPath_NoInheritance -NoTypeInformation -Encoding UTF8
    Write-Host "✓ Disabled inheritance report: $CsvPath_NoInheritance" -ForegroundColor Green
    Write-Host "  Folders/shares with disabled inheritance: $($noInheritanceResults.Count)" -ForegroundColor Yellow
}
else {
    $emptyInheritanceRow = [PSCustomObject]@{
        ShareName = ""
        LocalPath = ""
        Description = "No folders with disabled inheritance detected"
        TotalSizeGB = $null
        FileCount = 0
        FolderCount = 0
        Owner = ""
        InheritanceDisabled = $false
        ActiveUsers90d = ""
        NTFSPermissions = ""
    }
    @($emptyInheritanceRow) | Export-Csv -Path $CsvPath_NoInheritance -NoTypeInformation -Encoding UTF8
    Write-Host "! No folders found with disabled inheritance" -ForegroundColor Cyan
}

Write-Host "`n✓ Audit complete! All files saved to: $OutFolder" -ForegroundColor Green
Write-Host "`nFiles created:" -ForegroundColor Cyan
Write-Host "  1. SharedFoldersAudit_Main.csv - Main audit report" -ForegroundColor White
Write-Host "  2. SharedFoldersAudit_Permissions_Detailed.csv - Detailed permissions per identity" -ForegroundColor White
Write-Host "  3. SharedFoldersAudit_NoInheritance.csv - Folders with disabled inheritance" -ForegroundColor White
