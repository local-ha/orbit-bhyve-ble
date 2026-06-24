#!/bin/bash
# Install B-Hyve app on Android tablet using all split APKs from XAPK.
# Run on <your_linux_host>.

DEVICE="<TABLET_SERIAL>"
XAPK_DIR="/tmp/bhyve_xapk"
LOG="/tmp/adb_install.log"

echo "=== B-Hyve App Install via Split APKs ==="
echo "Device: $DEVICE"
echo ""

# Check device
if ! adb -s "$DEVICE" get-state > /dev/null 2>&1; then
    echo "ERROR: Device $DEVICE not connected"
    exit 1
fi

# Disable Play Protect verification
echo "Disabling Play Protect verification..."
adb -s "$DEVICE" shell settings put global verifier_verify_adb_installs 0
adb -s "$DEVICE" shell settings put global package_verifier_enable 0
sleep 1

# Build install-multiple command with arm64_v8a + hdpi + base + en language
# Select the right architecture and DPI for the Android Tablet
echo "Installing split APKs..."
echo "  Base APK: com.orbit.orbitsmarthome.apk"
echo "  Arch:     config.arm64_v8a.apk"
echo "  DPI:      config.xhdpi.apk"
echo "  Language: config.en.apk"
echo ""

adb -s "$DEVICE" install-multiple -r \
    "$XAPK_DIR/com.orbit.orbitsmarthome.apk" \
    "$XAPK_DIR/config.arm64_v8a.apk" \
    "$XAPK_DIR/config.xhdpi.apk" \
    "$XAPK_DIR/config.en.apk" \
    2>&1 | tee "$LOG"

echo ""
echo "Install log: $LOG"
echo ""

# Check result
if grep -q "Success" "$LOG"; then
    echo "✓ Installation SUCCESS"
    echo ""
    echo "Next steps:"
    echo "  1. Open B-Hyve app on the Android tablet"
    echo "  2. Pair with device MAC XX:XX:XX:XX:XX:XX"
    echo "  3. Run: python3 extract_networkkey.py"
else
    echo "✗ Installation FAILED"
    echo ""
    echo "Try disabling Play Protect manually on the tablet:"
    echo "  Open Play Store → Profile icon → Play Protect → Disable"
    echo "Then re-run this script."
fi
