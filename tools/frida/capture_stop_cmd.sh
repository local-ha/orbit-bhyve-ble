#!/bin/bash
# Automated capture of stop commands across multiple BLE sessions
# Each run: restart app → wait for BLE connect → start valve → stop valve → log
# Run on <your_linux_host>

DEVICE="<TABLET_SERIAL>"
PACKAGE="com.orbit.orbitsmarthome"
LOG="/tmp/stop_captures.log"
FRIDA_SCRIPT="/tmp/capture_gatt.js"

# Ensure Frida server is running
adb -s $DEVICE shell su -c 'pidof frida-server-new > /dev/null || /data/local/tmp/frida-server-new &'
sleep 3

echo "=== Capture run $(date) ===" >> $LOG

# Step 1: Kill and restart app
echo "Restarting app..."
adb -s $DEVICE shell am force-stop $PACKAGE
sleep 3
adb -s $DEVICE shell am start -n $PACKAGE/.MainActivity
sleep 10

# Step 2: Get PID and install Frida hooks
APP_PID=$(frida-ps -Ua 2>/dev/null | grep orbitsmarthome | awk '{print $1}')
echo "App PID: $APP_PID"

if [ -z "$APP_PID" ]; then
    echo "ERROR: App not running" >> $LOG
    exit 1
fi

FRIDA_LOG="/tmp/frida_session_$(date +%s).log"
timeout 120 frida -U -p $APP_PID -l $FRIDA_SCRIPT > $FRIDA_LOG 2>&1 &
FRIDA_PID=$!
sleep 5

if ! grep -q "hooks installed" $FRIDA_LOG; then
    echo "ERROR: Frida hooks failed" >> $LOG
    kill $FRIDA_PID 2>/dev/null
    exit 1
fi

# Step 3: Wait for BLE connection (check for init write to 6c71)
echo "Waiting for BLE connection..."
for i in $(seq 1 30); do
    if grep -q "6c71" $FRIDA_LOG; then
        echo "BLE connected!"
        break
    fi
    sleep 2
done

# Extract init write
INIT_TX=$(grep "6c71" $FRIDA_LOG | grep "GATT-W" | head -1 | sed 's/.*data=//')
echo "Init TX: $INIT_TX" >> $LOG

# Step 4: Count writes before valve command
WRITES_BEFORE=$(grep -c "GATT-W" $FRIDA_LOG)

# Step 5: Start valve - tap "Water Manually"
echo "Starting valve..."
# First need to find and tap Water Manually button
adb -s $DEVICE shell uiautomator dump /sdcard/ui.xml 2>/dev/null
WATER_BTN=$(adb -s $DEVICE shell cat /sdcard/ui.xml 2>/dev/null | tr '>' '\n' | grep "Water Manually" | grep -o 'bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1)
if [ -n "$WATER_BTN" ]; then
    # Parse bounds to get center
    X1=$(echo $WATER_BTN | grep -o '\[[0-9]*,' | head -1 | tr -d '[,')
    Y1=$(echo $WATER_BTN | grep -o ',[0-9]*\]' | head -1 | tr -d ',]')
    X2=$(echo $WATER_BTN | grep -o '\[[0-9]*,' | tail -1 | tr -d '[,')
    Y2=$(echo $WATER_BTN | grep -o ',[0-9]*\]' | tail -1 | tr -d ',]')
    CX=$(( (X1 + X2) / 2 ))
    CY=$(( (Y1 + Y2) / 2 ))
    echo "Water Manually button at ($CX, $CY)"
    adb -s $DEVICE shell input tap $CX $CY
    sleep 3

    # Tap Zone 1 '+' button
    adb -s $DEVICE shell uiautomator dump /sdcard/ui.xml 2>/dev/null
    ZONE1_ADD=$(adb -s $DEVICE shell cat /sdcard/ui.xml 2>/dev/null | tr '>' '\n' | grep "Zone 1" -A5 | grep 'bounds=' | tail -1 | grep -o 'bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"')
    # Just tap the right side where + should be
    adb -s $DEVICE shell input tap 760 305
    sleep 2

    # Tap Play button
    adb -s $DEVICE shell uiautomator dump /sdcard/ui.xml 2>/dev/null
    PLAY_BTN=$(adb -s $DEVICE shell cat /sdcard/ui.xml 2>/dev/null | tr '>' '\n' | grep -i 'play\|start\|run' | grep 'bounds=' | head -1 | grep -o 'bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"')
    # Tap center play button
    adb -s $DEVICE shell input tap 400 1170
    sleep 8
else
    echo "Water Manually button not found, trying fixed coordinates..."
    adb -s $DEVICE shell input tap 590 1080
    sleep 3
    adb -s $DEVICE shell input tap 760 305
    sleep 2
    adb -s $DEVICE shell input tap 400 1170
    sleep 8
fi

# Step 6: Wait for valve to start, then STOP it
echo "Valve should be running. Tapping Stop..."
sleep 5

# Find Stop button
adb -s $DEVICE shell uiautomator dump /sdcard/ui.xml 2>/dev/null
STOP_BTN=$(adb -s $DEVICE shell cat /sdcard/ui.xml 2>/dev/null | tr '>' '\n' | grep 'content-desc="Stop"' | grep 'clickable="true"' | head -1 | grep -o 'bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"')
if [ -n "$STOP_BTN" ]; then
    X1=$(echo $STOP_BTN | grep -o '\[[0-9]*,' | head -1 | tr -d '[,')
    Y1=$(echo $STOP_BTN | grep -o ',[0-9]*\]' | head -1 | tr -d ',]')
    X2=$(echo $STOP_BTN | grep -o '\[[0-9]*,' | tail -1 | tr -d '[,')
    Y2=$(echo $STOP_BTN | grep -o ',[0-9]*\]' | tail -1 | tr -d ',]')
    CX=$(( (X1 + X2) / 2 ))
    CY=$(( (Y1 + Y2) / 2 ))
    echo "Stop button at ($CX, $CY)"
    adb -s $DEVICE shell input tap $CX $CY
else
    echo "Stop button not found, using fixed coordinates..."
    adb -s $DEVICE shell input tap 400 1106
fi

sleep 5

# Step 7: Extract new writes (the stop command)
WRITES_AFTER=$(grep -c "GATT-W" $FRIDA_LOG)
NEW_WRITES=$((WRITES_AFTER - WRITES_BEFORE))
echo "New writes after stop: $NEW_WRITES"

echo "All GATT writes:" >> $LOG
grep "GATT-W" $FRIDA_LOG >> $LOG
echo "---" >> $LOG

# Cleanup
kill $FRIDA_PID 2>/dev/null
echo "Capture complete. See $LOG"
