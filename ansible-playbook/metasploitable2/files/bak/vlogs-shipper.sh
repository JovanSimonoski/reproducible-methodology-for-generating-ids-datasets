#!/bin/sh
# VictoriaLogs HTTP shipper for Metasploitable 2 (Ubuntu 8.04).
#
# Promtail can't run here (32-bit i686 - no Grafana 386 build; ancient
# glibc/kernel), so we tail the syslog files and POST each new line to
# VictoriaLogs' JSON stream ingestion API on port 9428 (open + reachable).
# Uses only /bin/sh, tail, perl, and curl - all present on the base image.
#
# Perl does the JSON string escaping (robust, unlike chained sed) and emits one
# JSON object per line:
#   {"message":"<line>","hostname":"<host>","timestamp":"<ISO8601 UTC>"}
# VictoriaLogs groups the stream by hostname and uses our timestamp.

VL_HOST="192.168.85.125"
VL_PORT="9428"
VL_URL="http://${VL_HOST}:${VL_PORT}/insert/jsonline?_stream_fields=hostname&_msg_field=message&_time_field=timestamp"

HOST="$(hostname)"
export SHIP_HOST="$HOST"

# Log files to ship (only those that exist are followed).
LOG_FILES="/var/log/syslog /var/log/auth.log /var/log/daemon.log /var/log/messages"
EXISTING=""
for f in $LOG_FILES; do
    [ -f "$f" ] && EXISTING="$EXISTING $f"
done

# If nothing exists, exit quietly.
[ -z "$EXISTING" ] && exit 0

# tail -F follows across rotation. Perl converts each line into a JSON object
# with proper escaping and a fresh UTC timestamp, then curl POSTs it.
# Perl streams (one curl per line) - syslog volume here is low, so this is fine.
tail -F $EXISTING 2>/dev/null | perl -e '
  $| = 1;
  my $host = $ENV{"SHIP_HOST"};
  while (my $line = <STDIN>) {
    chomp $line;
    next if $line eq "";
    $line =~ s/\\/\\\\/g;
    $line =~ s/"/\\"/g;
    $line =~ s/\t/\\t/g;
    $line =~ s/\r/\\r/g;
    $line =~ s/[\x00-\x1f]/ /g;
    my @t = gmtime(time);
    my $ts = sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",
                     $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
    print "{\"message\":\"$line\",\"hostname\":\"$host\",\"timestamp\":\"$ts\"}\n";
  }
' | while IFS= read -r json; do
    printf '%s\n' "$json" | curl -s --max-time 5 \
        -X POST -H 'Content-Type: application/stream+json' \
        --data-binary @- "$VL_URL" >/dev/null 2>&1
done
