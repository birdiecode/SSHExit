# SSH2SOCKS4Android

An Android app for managing SSH connection profiles and starting a local SOCKS5 proxy through an SSH dynamic port forward, equivalent to ssh -N -D LOCAL_PORT -i KEY USER@HOST.

## Features

- Save multiple SSH host profiles with username, SSH port, and local SOCKS5 port.
- Authenticate with an SSH password, a private key, or both.
- Start and stop the tunnel from the profile list.
- Keep the tunnel alive in a foreground service and show the local proxy address in its notification.
- Encrypt saved passwords, private keys, and key passphrases with an Android Keystore AES key.
- Verify server host keys with a trust-on-first-use prompt and pin the accepted fingerprint for later connections.

The app opens a local SOCKS5 listener on 127.0.0.1 only. Configure a SOCKS5-aware app to use the displayed address. Android does not automatically route all device traffic through this local proxy.

## Build

Open the project in Android Studio with JDK 17 and Gradle 8.13, or use an installed Gradle 8.13:

    gradle assembleDebug

The project uses Android Gradle Plugin 8.13.0, compile SDK 36, min SDK 26, and mwiede JSch 2.28.8.

## Security

SSH passwords, private keys, and key passphrases are stored as AES-GCM ciphertext using a key held in Android Keystore. Host keys are pinned after the user accepts their SHA-256 fingerprint. On first connection, compare the fingerprint shown by the app with a value obtained from the server administrator through a trusted channel before accepting it. If the server key changes, the app refuses the connection; delete and recreate the profile only after verifying the new fingerprint.

Keep the device lock screen enabled. Deleting a profile removes its encrypted key material from app preferences.