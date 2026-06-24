# Extracting Your Network Key

The Orbit B-Hyve XD encrypts its BLE data channel using an AES-128 key that is **specific to your Orbit account**, not specific to the physical device. Anyone in possession of the key can control all devices on your account, so treat it like a password.

There are three ways to obtain the key. The easiest is the included CLI wizard.

## Option 1 — Setup Wizard (recommended)

Run the all-in-one setup script:

```bash
cd scripts
pip install -r ../requirements.txt
python3 bhyve.py setup
```

The wizard will:

1. Prompt for your Orbit account email and password.
2. Authenticate against the Orbit cloud REST API and download the per-account network key.
3. Discover the BLE MAC address of your B-Hyve device by scanning.
4. Write the key, MAC, and zone count to a local config file in your home directory (default: `~/.config/orbit_bhyve/config.json`).

After running this, you can use `bhyve.py on 1 300`, etc., directly. You can also copy the key from the config file into the Home Assistant integration setup form.

If you prefer not to run the wizard interactively:

```bash
python3 bhyve.py setup --email you@example.com --password 'your-password'
```

The credentials are used only for the cloud authentication request; nothing is stored anywhere except the resulting network key in your local config file.

## Option 2 — Cloud API Direct Call

If you want to avoid the wizard and just retrieve the key, the Orbit cloud REST API exposes it on the user's profile endpoint after authentication. The script `scripts/extract_key.py` is a minimal example:

```bash
python3 scripts/extract_key.py --email you@example.com
```

It will prompt for the password, authenticate, and print the network key to stdout. No local files are written.

## Option 3 — From the Mobile App's Storage (advanced)

If you have a rooted Android device with the official B-Hyve app installed and paired, you can extract the key directly from the app's local storage without going through the cloud at all. This is useful for debugging cases where the cloud API path fails (rare, usually due to two-factor authentication or account changes).

The key lives in two places inside the app's data directory:

1. **HTTP cache.** The app caches the cloud response that delivered the key. Look in `/data/data/com.orbit.orbitsmarthome/cache/http-cache/` for files containing JSON like:
   ```json
   {"id":"...","user_id":"...","network_key":"<BASE64_NETWORK_KEY>","bridge_devices":[],"devices":[...]}
   ```
2. **MMKV persistent storage.** Tencent's MMKV format is used by the app for offline state. The relevant store is `mmkv-db-instance-users.<user_id>`. The MMKV format is a key-value flat file; the keys can be enumerated using any of the open-source MMKV reader libraries.

The `scripts/extract_networkkey.py` script automates pulling the cache file via ADB and parsing the `network_key` field. Usage:

```bash
adb devices                                     # confirm the tablet is connected
python3 scripts/extract_networkkey.py           # pulls and parses
```

The script requires:
- An ADB-connected Android device with the B-Hyve app installed and signed in to your account.
- Either a rooted device, or `adb shell` access via a debug-enabled build (rare for production apps).

## Format of the Key

The key is **16 bytes (128 bits)**. The cloud API returns it as base64; the integration and CLI accept it as 32 hex characters. To convert base64 to hex:

```python
import base64
b64 = "YOUR_BASE64_KEY"
print(base64.b64decode(b64).hex())
```

Or in shell:

```bash
echo -n 'YOUR_BASE64_KEY' | base64 -d | xxd -p
```

## Security Considerations

- **Treat the key as a password.** Anyone with the key can issue valve commands to all devices on your account, and can decrypt any captured BLE traffic from those devices.
- The key is **regenerated** if you delete and recreate your Orbit account, but is **not** rotated automatically.
- Storing the key in the Home Assistant integration's config entry persists it in HA's config directory (encrypted at rest only if your filesystem is encrypted). If your HA installation is exposed to untrusted users, take normal precautions.
- This project never transmits your key anywhere. The integration uses it only to decrypt notifications from and encrypt commands to your local BLE device.

## Troubleshooting

**The wizard says "authentication failed".**
- The Orbit cloud API uses OAuth-style flows that occasionally change. Try logging into the official app once to refresh your account state, then re-run the wizard.
- If you have two-factor authentication enabled on your Orbit account, the cloud-API path will likely fail. Use Option 3 (mobile-app extraction) instead.

**The wizard authenticates but reports "no devices found".**
- The cloud account must have at least one B-Hyve device registered.
- The first time you set up a B-Hyve, complete the registration in the official app first.

**The Home Assistant integration says "invalid_key".**
- The key must be exactly 32 hexadecimal characters (16 bytes). Strip any spaces, colons, or `0x` prefix before pasting.
