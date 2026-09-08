#!/bin/sh
# VictoriaLogs HTTP shipper for Metasploitable 2 (Ubuntu 8.04) - rev 2.
#
# Promtail can't run here (32-bit i686, ancient glibc/kernel), so we tail
# syslog files and POST NDJSON to VictoriaLogs on port 9428.
# Uses only /bin/sh, tail, perl, curl - all in the base image.
#
# rev 2 changes (volume + dedup fixes):
#   - Ship ONLY /var/log/syslog + /var/log/auth.log. On 8.04 sysklogd these
#     are DISJOINT (syslog excludes auth,authpriv). daemon.log and messages
#     are subsets of syslog - shipping them duplicated most lines 2-3x.
#     Do not add them back.
#   - tail -n 0: start at end-of-file. Without it every restart/reboot
#     re-shipped the last 10 lines of each file (duplicates in VL).
#   - tail's "==> /path <==" headers (emitted when tailing multiple files)
#     were being shipped as log lines; now they are parsed into a `file`
#     stream field instead.
#   - Noise filter: drops ntpdate SUCCESS lines and the sync-loop CRON line
#     (~7200 lines/day/host of timekeeping chatter). Failures still ship.
#   - Batching: up to 100 lines or 2 s per POST (was: one curl per line).
#     One retry on failure, then the batch is dropped (accepted trade-off;
#     no durable queue on these boxes).
VL_HOST="192.168.85.125"
VL_PORT="9428"
VL_URL="http://${VL_HOST}:${VL_PORT}/insert/jsonline?_stream_fields=hostname,file&_msg_field=message&_time_field=timestamp"
HOST="$(hostname)"

# Disjoint set - see header before changing.
LOG_FILES="/var/log/syslog /var/log/auth.log"

# Lines matching this perl regex are NOT shipped. Successes only - ntpdate
# failures ("no server suitable...") and other cron jobs still ship.
NOISE='ntpdate\[\d+\]: adjust time server|ntpdate\[\d+\]: step time server|CRON\[\d+\]: \(root\) CMD \(/usr/local/sbin/ntp-sync-loop\.sh\)'

EXISTING=""
for f in $LOG_FILES; do
    [ -f "$f" ] && EXISTING="$EXISTING $f"
done
[ -z "$EXISTING" ] && exit 0

# Default value of the `file` field until tail prints its first header
# (tail emits headers only when following 2+ files).
set -- $EXISTING
DEF_FILE="$1"

export SHIP_HOST="$HOST" VL_URL NOISE DEF_FILE

# -n 0 : start at EOF (no re-ship on restart);  -F : follow across rotation.
tail -n 0 -F $EXISTING 2>/dev/null | perl -e '
  $| = 1;
  my $host  = $ENV{SHIP_HOST};
  my $url   = $ENV{VL_URL};
  my $noise = $ENV{NOISE};
  my $file  = $ENV{DEF_FILE};
  my @buf;
  my $MAX_LINES = 100;   # flush threshold
  my $MAX_WAIT  = 2;     # seconds a line may sit buffered

  sub flush_buf {
    return unless @buf;
    my $tmp = "/tmp/.vlship.$$";
    if (open(my $fh, ">", $tmp)) {
      print $fh join("", @buf);
      close $fh;
      my $rc = system("curl -s --max-time 10 -X POST "
        . "-H \"Content-Type: application/stream+json\" "
        . "--data-binary \@$tmp \"$url\" >/dev/null 2>&1");
      if ($rc != 0) {           # one retry, then drop the batch
        sleep 1;
        system("curl -s --max-time 10 -X POST "
          . "-H \"Content-Type: application/stream+json\" "
          . "--data-binary \@$tmp \"$url\" >/dev/null 2>&1");
      }
      unlink $tmp;
    }
    @buf = ();
  }

  while (1) {
    my $line;
    eval {
      local $SIG{ALRM} = sub { die "timeout\n" };
      alarm($MAX_WAIT);
      $line = <STDIN>;
      alarm(0);
    };
    if ($@) { flush_buf(); next; }     # idle: flush whatever is buffered
    last unless defined $line;          # EOF: tail died, exit (init restarts)
    chomp $line;
    if ($line =~ /^==> (.+) <==$/) { $file = $1; next; }   # tail header
    next if $line eq "";
    next if $noise ne "" && $line =~ /$noise/;
    $line =~ s/\\/\\\\/g;
    $line =~ s/"/\\"/g;
    $line =~ s/\t/\\t/g;
    $line =~ s/\r/\\r/g;
    $line =~ s/[\x00-\x1f]/ /g;
    my @t = gmtime(time);
    my $ts = sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",
                     $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
    push @buf, "{\"message\":\"$line\",\"hostname\":\"$host\","
             . "\"file\":\"$file\",\"timestamp\":\"$ts\"}\n";
    flush_buf() if @buf >= $MAX_LINES;
  }
  flush_buf();
'
