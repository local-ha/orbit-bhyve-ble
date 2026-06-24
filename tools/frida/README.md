# Frida Instrumentation Scripts

Frida is a dynamic instrumentation toolkit that allows hooking running processes at the function level. This directory contains the Frida JavaScript scripts and helper shell scripts that were used during reverse engineering to observe the official Orbit B-Hyve mobile application's encryption behavior at runtime.

These scripts are **not required** to use the integration. They are provided as a reference for anyone investigating similar BLE protocols or extending this work.

## Files

| File | Purpose |
|---|---|
| `aes_brute.js` | Hooks `BluetoothGatt#writeCharacteristic` and logs the bytes the application is about to send. Useful for capturing pre-encryption plaintext or post-encryption ciphertext (depending on hook placement). |
| `aes_counter_test.js` | Probes whether the application's AES is implemented in Java's `javax.crypto`, native libcrypto, or pure JavaScript. Used to narrow down where the cipher routine lives. |
| `install_bhyve_app.sh` | Helper script to install the official B-Hyve app onto a Frida-instrumented Android device. |
| `tablet_control.sh` | ADB UI-automation helpers (tap, swipe, screencap) used to drive the application during instrumentation. Customize the coordinates for your screen size before use. |
| `capture_stop_cmd.sh` | Convenience script to launch the app, navigate to the manual-control screen, and capture a single STOP-watering BLE write — useful for getting a known-plaintext sample. |

## Setup

You will need:

1. An **Android device or emulator** that is rooted (Magisk is the simplest approach). The Frida server cannot be loaded without root.
2. A **Frida server binary** matching the architecture of the device (`arm64-v8a` for most modern Android phones/tablets, `x86_64` for emulators). Download from the [Frida releases page](https://github.com/frida/frida/releases) — pick `frida-server-VERSION-android-ARCH.xz`.
3. The **Frida CLI tools** installed on your host:
   ```bash
   pip install frida-tools
   ```
4. The official B-Hyve mobile application installed on the device and signed in to your Orbit account.

## Loading the Frida Server

```bash
adb push frida-server-VERSION-android-arm64 /data/local/tmp/frida-server
adb shell chmod +x /data/local/tmp/frida-server
adb shell "su -c '/data/local/tmp/frida-server &'"
```

Verify the server is reachable:

```bash
frida-ps -U
```

You should see a list of running Android processes.

## Attaching a Hook

To attach `aes_brute.js` while the application is running:

```bash
frida -U -l aes_brute.js com.orbit.orbitsmarthome
```

Use `-l <script>` to load the script and the package name as the target. For best results, attach **before** triggering BLE writes from the app — Frida will then log every write.

## What You'll See

`aes_brute.js` produces output like:

```
[BLE-WRITE] UUID=00006c72-fe32-4f58-8b78-98e42b2c047f len=20 data=11103b7ae2c969d6c71c5ecb733e46dee7db9303
```

Each line is one ATT Write to the device. The `data=` field is the on-wire ciphertext bytes (post-encryption). Pair this with a `btsnoop` capture from the same session to confirm the hook is seeing what the BLE adapter is seeing.

To capture **plaintext** (pre-encryption) you'll need a different hook position — usually inside the application's BLE service module rather than at the `BluetoothGatt` boundary. The exact hook location depends on the mobile-app implementation; this is left as an exercise for the reader, since it varies by app version.

## Caveats

- **Application updates can break hooks.** When the mobile application is updated, internal class names and method signatures may change, breaking hooks that target them. Hooks at standard Android API boundaries (`BluetoothGatt`, `BluetoothGattCharacteristic`) are stable across app versions.
- **Frida is detectable.** Some applications include Frida-detection logic. The B-Hyve app at the time of this work did not appear to. If a future version does, you may need anti-anti-Frida measures (gadget injection, native bypasses) — outside the scope of this project.
- **Use with the device you own.** These tools are intended for use against your own device and your own Orbit account. Do not use them to interfere with devices or accounts you do not own.
