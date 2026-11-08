# SentinelLOLBins - authorised Sysmon collection helper
# =====================================================
# Run inside the isolated Windows 10 VM, in an Administrator PowerShell:
#
#   . C:\Lab\collect_sysmon.ps1
#   Start-Scenario "BEN-001"
#   whoami /all
#   Export-Scenario -Label 0 -Technique "none" -Description "whoami /all" `
#       -AuthorisedBy "Sapna Sadhwani" -PayloadNote "none"
#
# Output files (created automatically):
#   C:\Lab\out\sysmon_events.csv    Event ID 1, one row per process creation
#   C:\Lab\out\sysmon_network.csv   Event ID 3, one row per network connection
#   C:\Lab\out\scenarios.csv        one row per scenario/run
#
# This script never invents fields. It keeps the raw Sysmon values and converts
# Sysmon's hexadecimal ProcessId / ParentProcessId to decimal because the
# schema adapter expects decimal IDs.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:SysmonLog  = "Microsoft-Windows-Sysmon/Operational"
$script:OutDir     = "C:\Lab\out"
$script:EventsCsv  = Join-Path $script:OutDir "sysmon_events.csv"
$script:NetworkCsv = Join-Path $script:OutDir "sysmon_network.csv"
$script:ScenariosCsv = Join-Path $script:OutDir "scenarios.csv"
$script:StateFile  = Join-Path $script:OutDir "current_scenario.json"

New-Item -ItemType Directory -Force -Path $script:OutDir | Out-Null

function ConvertFrom-SysmonId {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    $v = $Value.Trim()
    if ($v -match '^0x[0-9A-Fa-f]+$') {
        return [Convert]::ToInt64($v.Substring(2), 16).ToString()
    }
    $n = 0L
    if ([int64]::TryParse($v, [ref]$n)) { return $n.ToString() }
    return ""
}

function ConvertTo-UtcDateTime {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "Empty Sysmon UtcTime" }
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor `
              [Globalization.DateTimeStyles]::AdjustToUniversal
    $formats = @(
        "yyyy-MM-dd HH:mm:ss.fff",
        "yyyy-MM-dd HH:mm:ss.ffffff",
        "yyyy-MM-dd HH:mm:ss.fffffff",
        "yyyy-MM-ddTHH:mm:ss.fffZ",
        "yyyy-MM-ddTHH:mm:ss.ffffffZ",
        "yyyy-MM-ddTHH:mm:ss.fffffffZ",
        "o"
    )
    $dt = [datetime]::MinValue
    foreach ($f in $formats) {
        if ([datetime]::TryParseExact($Value, $f,
                [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) {
            return $dt
        }
    }
    return [datetime]::Parse($Value,
        [Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Get-SysmonData {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = @{}
    $nodes = $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']")
    foreach ($node in $nodes) {
        $name = $node.GetAttribute("Name")
        if ($name) { $data[$name] = [string]$node.InnerText }
    }
    return $data
}

function Add-CsvRows {
    param(
        [string]$Path,
        [object[]]$Rows,
        [string[]]$Columns
    )
    if ($null -eq $Rows -or $Rows.Count -eq 0) { return }
    $isNew = (-not (Test-Path $Path)) -or ((Get-Item $Path).Length -eq 0)
    if ($isNew) {
        $Rows | Select-Object $Columns |
            Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    } else {
        $Rows | Select-Object $Columns |
            Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Append
    }
}

function Get-LastSysmonRecordId {
    param([int]$EventId)
    $ev = Get-WinEvent -FilterHashtable @{
        LogName = $script:SysmonLog
        Id      = $EventId
    } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -ne $ev) { return [int64]$ev.RecordId }
    return [int64]0
}

function Start-Scenario {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScenarioId
    )

    if (Test-Path $script:StateFile) {
        $active = Get-Content $script:StateFile -Raw | ConvertFrom-Json
        throw "Scenario '$($active.scenario_id)' is still active. Run Export-Scenario first (or Cancel-Scenario)."
    }

    $start = (Get-Date).ToUniversalTime()
    [pscustomobject]@{
        scenario_id       = $ScenarioId
        start_utc         = $start.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        start_record_id_1 = Get-LastSysmonRecordId -EventId 1
        start_record_id_3 = Get-LastSysmonRecordId -EventId 3
    } | ConvertTo-Json | Set-Content -Path $script:StateFile -Encoding UTF8

    Write-Host ""
    Write-Host "STARTED $ScenarioId at $($start.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))" -ForegroundColor Cyan
    Write-Host "Now run the scenario command. Then call Export-Scenario." -ForegroundColor Cyan
}

function Cancel-Scenario {
    [CmdletBinding()]
    param()
    if (Test-Path $script:StateFile) {
        Remove-Item $script:StateFile -Force
        Write-Host "Active scenario cancelled; no rows were tagged." -ForegroundColor Yellow
    } else {
        Write-Host "No active scenario." -ForegroundColor Yellow
    }
}

function Export-Scenario {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 1)]
        [int]$Label,

        [Parameter(Mandatory = $true)]
        [string]$Technique,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$AuthorisedBy,

        [string]$PayloadNote = "none"
    )

    if (-not (Test-Path $script:StateFile)) {
        throw "No active scenario. Run Start-Scenario first."
    }

    $state = Get-Content $script:StateFile -Raw | ConvertFrom-Json
    $start = [datetime]::Parse($state.start_utc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor `
        [Globalization.DateTimeStyles]::AdjustToUniversal)
    $scenarioId = [string]$state.scenario_id
    $startRecord1 = [int64]$state.start_record_id_1
    $startRecord3 = [int64]$state.start_record_id_3

    # Sysmon writes the process-creation record shortly AFTER the process
    # starts. On this low-memory VM that delay is long enough that a single
    # short sleep misses very fast commands (ipconfig, net user, certutil,
    # robocopy, reg, rundll32). Wait at least 3 s, then keep polling the
    # EventRecordID bookmark until a new Event ID 1 record actually appears.
    Start-Sleep -Seconds 3
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        if ((Get-LastSysmonRecordId -EventId 1) -gt $startRecord1) { break }
        Start-Sleep -Milliseconds 400
    }
    # Give child processes (e.g. conhost, net1, msiexec -> calc) time to write.
    Start-Sleep -Milliseconds 2000

    $end = (Get-Date).ToUniversalTime()
    $graceEnd = $end.AddSeconds(5)

    $events = @()
    try {
        $events = Get-WinEvent -LogName $script:SysmonLog -FilterXPath `
            "*[System[(EventID=1) and (EventRecordID > $startRecord1)]]" `
            -ErrorAction Stop
    } catch {
        $events = @()
    }

    $network = @()
    try {
        $network = Get-WinEvent -LogName $script:SysmonLog -FilterXPath `
            "*[System[(EventID=3) and (EventRecordID > $startRecord3)]]" `
            -ErrorAction Stop
    } catch {
        $network = @()
    }

    $eventColumns = @(
        "UtcTime", "Computer", "EventID", "ProcessId", "ParentProcessId",
        "Image", "CommandLine", "ParentImage", "ParentCommandLine", "User",
        "IntegrityLevel", "CurrentDirectory", "LogonId", "Hashes", "RuleName",
        "scenario_id"
    )
    $networkColumns = @(
        "UtcTime", "ProcessId", "Image", "DestinationIp", "DestinationPort",
        "Protocol", "scenario_id"
    )

    $eventRows = New-Object System.Collections.Generic.List[object]
    $networkRows = New-Object System.Collections.Generic.List[object]

    foreach ($ev in $events) {
        $d = Get-SysmonData $ev
        $utc = ConvertTo-UtcDateTime $d["UtcTime"]
        if ($utc -lt $start.AddSeconds(-2) -or $utc -gt $graceEnd) { continue }
        $eventRows.Add([pscustomobject]@{
            UtcTime           = $utc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            Computer          = $d["Computer"]
            EventID           = 1
            ProcessId         = ConvertFrom-SysmonId $d["ProcessId"]
            ParentProcessId   = ConvertFrom-SysmonId $d["ParentProcessId"]
            Image             = $d["Image"]
            CommandLine       = $d["CommandLine"]
            ParentImage       = $d["ParentImage"]
            ParentCommandLine = $d["ParentCommandLine"]
            User              = $d["User"]
            IntegrityLevel    = $d["IntegrityLevel"]
            CurrentDirectory  = $d["CurrentDirectory"]
            LogonId           = $d["LogonId"]
            Hashes            = $d["Hashes"]
            RuleName          = $d["RuleName"]
            scenario_id       = $scenarioId
        })
    }

    foreach ($ev in $network) {
        $d = Get-SysmonData $ev
        $utc = ConvertTo-UtcDateTime $d["UtcTime"]
        if ($utc -lt $start.AddSeconds(-2) -or $utc -gt $graceEnd) { continue }
        $networkRows.Add([pscustomobject]@{
            UtcTime        = $utc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            ProcessId      = ConvertFrom-SysmonId $d["ProcessId"]
            Image          = $d["Image"]
            DestinationIp  = $d["DestinationIp"]
            DestinationPort= $d["DestinationPort"]
            Protocol       = $d["Protocol"]
            scenario_id    = $scenarioId
        })
    }

    Add-CsvRows -Path $script:EventsCsv -Rows $eventRows -Columns $eventColumns
    Add-CsvRows -Path $script:NetworkCsv -Rows $networkRows -Columns $networkColumns

    $scenarioRow = [pscustomobject]@{
        scenario_id        = $scenarioId
        expected_label     = $Label
        technique_expected = $Technique
        start_utc          = $start.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        end_utc            = $end.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        description        = $Description
        authorised_by      = $AuthorisedBy
        payload_note       = $PayloadNote
    }
    Add-CsvRows -Path $script:ScenariosCsv -Rows @($scenarioRow) -Columns @(
        "scenario_id", "expected_label", "technique_expected", "start_utc",
        "end_utc", "description", "authorised_by", "payload_note"
    )

    Remove-Item $script:StateFile -Force

    Write-Host ""
    Write-Host "EXPORTED $scenarioId : $($eventRows.Count) Event ID 1 row(s), $($networkRows.Count) Event ID 3 row(s)." -ForegroundColor Green
    if ($eventRows.Count -eq 0) {
        Write-Host "WARNING: no Event ID 1 rows in this window. Check the command actually ran." -ForegroundColor Yellow
    }
    Write-Host "Files: $script:EventsCsv | $script:NetworkCsv | $script:ScenariosCsv" -ForegroundColor Green
}

function Show-Collection {
    [CmdletBinding()]
    param()
    foreach ($p in @($script:EventsCsv, $script:NetworkCsv, $script:ScenariosCsv)) {
        if (Test-Path $p) {
            $n = (Import-Csv $p | Measure-Object).Count
            Write-Host "$p : $n row(s)" -ForegroundColor Cyan
        } else {
            Write-Host "$p : not created yet" -ForegroundColor Yellow
        }
    }
}

function Run-Benign {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioId,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    Start-Scenario $ScenarioId
    & $Command
    Export-Scenario -Label 0 -Technique "none" -Description $Description `
        -AuthorisedBy "Sapna Sadhwani" -PayloadNote "none"
}

function Run-Attack {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioId,
        [Parameter(Mandatory = $true)][string]$Technique,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Command,
        [string]$PayloadNote = "harmless: calc.exe / local lab file, no malware"
    )
    Start-Scenario $ScenarioId
    & $Command
    Export-Scenario -Label 1 -Technique $Technique -Description $Description `
        -AuthorisedBy "Sapna Sadhwani" -PayloadNote $PayloadNote
}

Write-Host ""
Write-Host "SentinelLOLBins Sysmon collection helper loaded." -ForegroundColor Green
Write-Host "Output folder: $script:OutDir" -ForegroundColor Green
Write-Host "Use: Start-Scenario 'BEN-001'; <command>; Export-Scenario -Label 0 -Technique 'none' -Description '...' -AuthorisedBy 'Sapna Sadhwani'" -ForegroundColor Green
Write-Host ""
