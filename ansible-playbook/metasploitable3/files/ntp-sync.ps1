# Time sync for Metasploitable 3 (Windows Server 2008 R2) via a high source port.
#
# WHY: the internet-gateway NAT drops NTP replies to source-port-123 traffic, so
# the W32Time SERVICE can never sync. w32tm /stripchart uses a high (ephemeral)
# source port the NAT allows, so it reliably MEASURES the offset to FINKI. This
# script uses that to measure, then steps the clock. Run every minute via Task
# Scheduler (Windows analog of the metas2 ntpdate cron).
#
# SIGN CONVENTION (verified on the box): w32tm reports offset o = (server - local).
#   correct_time = local + o   ==>  (Get-Date).AddSeconds($offset)
# A negative offset means local is AHEAD (subtract); positive means BEHIND (add).
# AddSeconds handles both signs correctly - no branching, no feedback loop.
#
# SAFETY CLAMP: if the measured offset exceeds $maxStepSeconds, the script LOGS
# and REFUSES to step (a single bad reading can't run the clock away). On first
# setup, if the box is more than the clamp off, run once with -Force.

param([switch]$Force)

$ntpServer      = "ntp.finki.ukim.mk"
$logFile        = "C:\Windows\Temp\ntp-sync.log"
$maxStepSeconds = 3600     # refuse steps larger than 1 hour unless -Force

function Log($msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $logFile -Value "$ts  $msg"
}

try {
    $out = & w32tm /stripchart /computer:$ntpServer /samples:4 /dataonly 2>&1

    $offsets = @()
    foreach ($line in $out) {
        if ($line -match ',\s*([+-]\d+\.\d+)s') {
            $offsets += [double]$matches[1]
        }
    }

    if ($offsets.Count -eq 0) {
        Log "No offset samples parsed (server unreachable?). Output: $out"
        exit 1
    }

    # Median for robustness against a single bad sample.
    $sorted = $offsets | Sort-Object
    $median = $sorted[[math]::Floor($sorted.Count / 2)]

    # Safety clamp: refuse an absurd step unless forced.
    if ([math]::Abs($median) -gt $maxStepSeconds -and -not $Force) {
        Log ("REFUSED: offset {0:+0.000;-0.000}s exceeds clamp {1}s. Not stepping. Run with -Force if this is a first-time large correction." -f $median, $maxStepSeconds)
        exit 2
    }

    # Only step if meaningfully off (> 0.05s) to avoid needless churn.
    if ([math]::Abs($median) -gt 0.05) {
        # correct = local + offset (offset already carries the right sign).
        $correct = (Get-Date).AddSeconds($median)
        Set-Date -Date $correct | Out-Null
        Log ("Stepped clock by {0:+0.000;-0.000}s (median of {1} samples)" -f $median, $offsets.Count)
    } else {
        Log ("In sync (median offset {0:+0.000;-0.000}s, no step)" -f $median)
    }
}
catch {
    Log "ERROR: $_"
    exit 1
}
