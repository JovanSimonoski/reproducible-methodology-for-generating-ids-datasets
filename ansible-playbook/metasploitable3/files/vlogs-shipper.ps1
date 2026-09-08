# vlogs-shipper.ps1 - VictoriaLogs Event Log shipper for Server 2008 R2.
# PowerShell 2.0 compatible (no ConvertTo-Json, no Invoke-RestMethod).
#
# One pass per invocation: for each channel, read events with
# EventRecordID > last shipped position, POST them as NDJSON to
# VictoriaLogs, and advance the position ONLY on successful POST.
# -> no duplicates on restart, no loss during VictoriaLogs downtime
#    (backlog drains at MaxPerPass per channel per minute).
# First run initializes positions to the current tail (ships from now on,
# not the whole event-log history).
# Timestamps are the event's own TimeCreated (UTC), not read time.
# Run as SYSTEM (Security channel needs it) via a per-minute scheduled task.

$VlUrl      = "http://192.168.85.125:9428/insert/jsonline?_stream_fields=hostname,channel&_msg_field=message&_time_field=timestamp"
$Channels   = @("System", "Application", "Security")
$StateDir   = "C:\ProgramData\vlogs-shipper"
$PosFile    = Join-Path $StateDir "positions.txt"
$LogFile    = Join-Path $StateDir "shipper.log"
$MaxPerPass = 1000        # per channel per pass; backlog drains gradually
$ExcludeEventIds = @()    # e.g. @(5156) if firewall auditing ever floods

# --- single-instance guard (a backlog pass may exceed the 60s cron period) ---
$mutex = New-Object System.Threading.Mutex($false, "Global\vlogs-shipper")
if (-not $mutex.WaitOne(0)) { exit 0 }

if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir | Out-Null }

function Log([string]$msg) {
    $line = ("{0} {1}" -f (Get-Date -Format s), $msg)
    Add-Content -Path $LogFile -Value $line
}

# keep the local log from growing forever
if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 5MB)) { Clear-Content $LogFile }

# PS 2.0 quirk: event Message formatting can return null under non-en-US
# culture; pin the thread culture as a workaround.
[System.Threading.Thread]::CurrentThread.CurrentCulture = New-Object System.Globalization.CultureInfo("en-US")

function Escape-Json([string]$s) {
    if ($s -eq $null) { return "" }
    $s = $s.Replace('\', '\\').Replace('"', '\"')
    $s = $s -replace "`r", '\r' -replace "`n", '\n' -replace "`t", '\t'
    $s = $s -replace '[\x00-\x1f]', ' '
    return $s
}

function Get-MaxRecordId([string]$channel) {
    try {
        $e = Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction Stop
        return [long]$e.RecordId
    } catch { return [long]0 }
}

# --- load positions (plain "Channel=RecordId" lines; PS2 has no JSON) ---
$pos = @{}
if (Test-Path $PosFile) {
    Get-Content $PosFile | ForEach-Object {
        if ($_ -match '^(.+)=(\d+)$') { $pos[$matches[1]] = [long]$matches[2] }
    }
}

$hostn = $env:COMPUTERNAME.ToLower()
$utf8  = New-Object System.Text.UTF8Encoding($false)

foreach ($ch in $Channels) {
    if (-not $pos.ContainsKey($ch)) {
        # First run for this channel: start at the current tail.
        $pos[$ch] = Get-MaxRecordId $ch
        Log ("init {0} position={1}" -f $ch, $pos[$ch])
        continue
    }

    $last  = $pos[$ch]
    $xpath = "*[System[EventRecordID > $last]]"
    $events = @()
    try {
        $events = @(Get-WinEvent -LogName $ch -FilterXPath $xpath -Oldest `
                    -MaxEvents $MaxPerPass -ErrorAction Stop)
    } catch {
        $events = @()   # "no events match" throws in PS2 - treat as empty
    }
    if ($events.Count -eq 0) { continue }

    $sb = New-Object System.Text.StringBuilder
    $newLast = $last
    $shipped = 0
    foreach ($e in $events) {
        $rid = [long]$e.RecordId
        if ($rid -gt $newLast) { $newLast = $rid }
        if ($ExcludeEventIds -contains $e.Id) { continue }
        $msg = $e.Message
        if (-not $msg) { $msg = ("(no message) provider={0} id={1}" -f $e.ProviderName, $e.Id) }
        $ts = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        [void]$sb.Append('{"message":"' + (Escape-Json $msg) `
            + '","hostname":"'  + $hostn + '"' `
            + ',"channel":"'    + $ch + '"' `
            + ',"provider":"'   + (Escape-Json $e.ProviderName) + '"' `
            + ',"event_id":"'   + $e.Id + '"' `
            + ',"level":"'      + (Escape-Json $e.LevelDisplayName) + '"' `
            + ',"timestamp":"'  + $ts + '"}' + "`n")
        $shipped++
    }

    if ($sb.Length -gt 0) {
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Proxy = $null
            $wc.Headers.Add("Content-Type", "application/stream+json")
            [void]$wc.UploadData($VlUrl, "POST", $utf8.GetBytes($sb.ToString()))
            $pos[$ch] = $newLast
            Log ("shipped {0} count={1} upto={2}" -f $ch, $shipped, $newLast)
        } catch {
            # Position NOT advanced -> this batch is retried next pass.
            Log ("POST FAILED {0}: {1}" -f $ch, $_.Exception.Message)
        }
    } else {
        $pos[$ch] = $newLast   # everything in range was excluded
    }
}

# --- persist positions ---
$out = @()
foreach ($k in $pos.Keys) { $out += ("{0}={1}" -f $k, $pos[$k]) }
Set-Content -Path $PosFile -Value $out

[void]$mutex.ReleaseMutex()
exit 0
