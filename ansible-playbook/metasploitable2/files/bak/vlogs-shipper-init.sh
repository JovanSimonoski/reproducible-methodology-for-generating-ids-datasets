#!/bin/sh
### BEGIN INIT INFO
# Provides:          vlogs-shipper
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Ship logs to VictoriaLogs over HTTP
### END INIT INFO

DAEMON=/usr/local/bin/vlogs-shipper.sh
PIDFILE=/var/run/vlogs-shipper.pid
NAME=vlogs-shipper

case "$1" in
  start)
    echo -n "Starting $NAME: "
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        echo "already running"
        exit 0
    fi
    # Run detached; record PID
    nohup "$DAEMON" >/dev/null 2>&1 &
    echo $! > "$PIDFILE"
    echo "OK"
    ;;
  stop)
    echo -n "Stopping $NAME: "
    if [ -f "$PIDFILE" ]; then
        # Kill the shipper and its tail child
        PID="$(cat $PIDFILE)"
        pkill -P "$PID" 2>/dev/null
        kill "$PID" 2>/dev/null
        rm -f "$PIDFILE"
        echo "OK"
    else
        echo "not running"
    fi
    # Also clean up any stray tail -F from this script
    pkill -f "tail -F .*/var/log/syslog" 2>/dev/null || true
    ;;
  restart)
    "$0" stop
    sleep 1
    "$0" start
    ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        echo "$NAME running (pid $(cat $PIDFILE))"
    else
        echo "$NAME not running"
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac
exit 0
