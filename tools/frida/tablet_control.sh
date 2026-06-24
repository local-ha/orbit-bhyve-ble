#!/bin/bash
# Tablet automation helpers for B-Hyve reverse engineering
# Run on <your_linux_host> (has ADB access to Android tablet <TABLET_SERIAL>)

DEVICE="<TABLET_SERIAL>"
PACKAGE="com.orbit.orbitsmarthome"
FRIDA_SERVER="/data/local/tmp/frida-server-new"

case "$1" in
    bt-restart)
        echo "Restarting Bluetooth..."
        adb -s $DEVICE shell am force-stop $PACKAGE
        adb -s $DEVICE shell svc bluetooth disable
        sleep 3
        adb -s $DEVICE shell svc bluetooth enable
        sleep 8
        adb -s $DEVICE shell su -c 'ls -la /data/misc/bluetooth/logs/'
        echo "Bluetooth restarted."
        ;;

    app-start)
        echo "Starting B-Hyve app..."
        adb -s $DEVICE shell am start -n $PACKAGE/.MainActivity
        sleep 3
        echo "App started."
        ;;

    app-stop)
        echo "Stopping B-Hyve app..."
        adb -s $DEVICE shell am force-stop $PACKAGE
        echo "App stopped."
        ;;

    app-pid)
        frida-ps -Ua 2>/dev/null | grep orbitsmarthome | awk '{print $1}'
        ;;

    frida-start)
        echo "Starting Frida server..."
        adb -s $DEVICE shell su -c "killall frida-server-new 2>/dev/null"
        adb -s $DEVICE shell su -c "$FRIDA_SERVER -D &"
        sleep 3
        frida-ps -U 2>/dev/null | head -3
        echo "Frida server running."
        ;;

    frida-stop)
        echo "Stopping Frida..."
        killall frida 2>/dev/null
        adb -s $DEVICE shell su -c "killall frida-server-new 2>/dev/null"
        echo "Frida stopped."
        ;;

    snoop-pull)
        echo "Pulling BT snoop log..."
        LATEST=$(adb -s $DEVICE shell su -c 'ls -t /data/misc/bluetooth/logs/*.curf 2>/dev/null | head -1')
        if [ -z "$LATEST" ]; then
            echo "No snoop file found."
            exit 1
        fi
        echo "Latest: $LATEST"
        adb -s $DEVICE shell su -c "cp $LATEST /sdcard/bt_snoop_latest.log"
        adb -s $DEVICE pull /sdcard/bt_snoop_latest.log /tmp/bt_snoop_latest.log
        ls -la /tmp/bt_snoop_latest.log
        ;;

    capture-cycle)
        echo "=== Full capture cycle ==="
        $0 app-stop
        sleep 1
        $0 bt-restart
        sleep 2
        $0 app-start
        echo "Waiting 30s for BLE connection and data exchange..."
        sleep 30
        $0 snoop-pull
        echo "=== Capture complete ==="
        ;;

    status)
        echo "=== Tablet Status ==="
        echo "ADB:" $(adb -s $DEVICE get-state 2>/dev/null)
        echo "BT:" $(adb -s $DEVICE shell settings get global bluetooth_on)
        echo "App:" $(frida-ps -Ua 2>/dev/null | grep orbitsmarthome | awk '{print "PID="$1}')
        echo "Snoop files:"
        adb -s $DEVICE shell su -c 'ls -la /data/misc/bluetooth/logs/' 2>/dev/null
        echo "Frida:" $(frida-ps -U 2>/dev/null | wc -l) "processes visible"
        ;;

    wake)
        echo "Waking tablet screen..."
        adb -s $DEVICE shell input keyevent KEYCODE_WAKEUP
        sleep 1
        adb -s $DEVICE shell input keyevent KEYCODE_MENU
        ;;

    *)
        echo "Usage: $0 {bt-restart|app-start|app-stop|app-pid|frida-start|frida-stop|snoop-pull|capture-cycle|status|wake}"
        exit 1
        ;;
esac
