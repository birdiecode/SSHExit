# SSHExit

**English** · [Русский](README.ru.md)

An Android app for managing SSH connection profiles and starting a local SOCKS5 proxy through an SSH dynamic port forward, equivalent to ssh -N -D LOCAL_PORT -i KEY -J JUMP USER@HOST.

## Features

- Save multiple SSH host profiles with username, SSH port, and local SOCKS5 port.
- Configure an optional SSH jump server using ProxyJump (-J), with its own username and password or vault key.
- Keep reusable SSH private keys in a separate encrypted vault and assign different keys to the target and jump server.
- Authenticate with an SSH password, a private key, or both.
- Start and stop the tunnel from the profile list.
- Keep the tunnel alive in a foreground service and show the local proxy address in its notification.
- Encrypt saved passwords, private keys, and key passphrases with an Android Keystore AES key.
- Verify server host keys with a trust-on-first-use prompt and pin the accepted fingerprint for later connections.

The app opens a local SOCKS5 listener on 127.0.0.1 only. Configure a SOCKS5-aware app to use the displayed address. Android does not automatically route all device traffic through this local proxy.

## Android identity

The application is named **SSHExit**, with application ID `host.birdiecode.sshexit`.
Android installs it separately from the earlier `ru.birdiecode.ssh2socks4android` app.
Saved profiles, passwords and private keys in the old installation are not transferred automatically.

## Signed releases

Create a PKCS12 signing keystore on a trusted computer. The script prompts for the keystore identity and password and refuses to overwrite an existing file:

    bash scripts/generate-signing-keystore.sh "$HOME/ssh2socks-release.p12" ssh2socks-release

Use the same strong password for the keystore and key entry. Back up the keystore and password offline; without them, future APK updates cannot be signed with the same identity. Never commit the keystore or put it in a workflow log.

With GitHub CLI authenticated to this repository, add the signing values as repository secrets:

    REPO=birdiecode/SSHExit
    base64 < "$HOME/ssh2socks-release.p12" | tr -d '\n' | gh secret set ANDROID_KEYSTORE_BASE64 --repo "$REPO"
    gh secret set ANDROID_KEY_ALIAS --repo "$REPO" --body ssh2socks-release
    read -rsp "Keystore password: " KEYSTORE_PASSWORD; printf '\n'
    printf '%s' "$KEYSTORE_PASSWORD" | gh secret set ANDROID_KEYSTORE_PASSWORD --repo "$REPO"
    printf '%s' "$KEYSTORE_PASSWORD" | gh secret set ANDROID_KEY_PASSWORD --repo "$REPO"
    unset KEYSTORE_PASSWORD

After the workflow changes are merged to the default branch, open **Actions → Android Release → Run workflow**, enter a version in `X.Y.Z` format, and run it. The workflow increments `versionCode`, updates `versionName`, builds and verifies a signed release APK, commits the version change to `main`, creates a `vX.Y.Z` tag, and publishes a GitHub Release with the APK attached.

## Security

SSH passwords, jump server passwords, private keys, and key passphrases are stored as AES-GCM ciphertext using a key held in Android Keystore. Host keys are pinned after the user accepts their SHA-256 fingerprint. On first connection, compare the fingerprint shown by the app with a value obtained from the server administrator through a trusted channel before accepting it. If the server key changes, the app refuses the connection; delete and recreate the profile only after verifying the new fingerprint.

Keep the device lock screen enabled. Deleting a profile removes its encrypted key material from app preferences.

## SSH TUN development branch

The VPN implementation in this branch is incomplete and is not ready for deployment.
The Android consent flow, VpnService interface, protected SSH sockets, custom
point-to-point OpenSSH channel and server configuration script are present.
Each profile now owns an independent lifecycle, SSH chain, SOCKS listener,
authentication requests and scheduled transport health checks. Disconnect actions
are scoped to one profile; the notification can disconnect all. Manual cancellation
stops scheduled reconnect attempts. Multiple SOCKS connections are supported; the
current service explicitly reserves the Android VPN for one connection until the
shared VPN packet runtime and address allocation are integrated.

The packet codec includes the OpenSSH length and address-family fields (2 for IPv4,
24 for IPv6). Unit tests check wire vectors, fragmented input, prefix routing,
shell syntax, unsafe interface parameters, valid lifecycle transitions and isolated
connection cancellation. Actual concurrent sessions and network recovery still
require integration verification.

Still required before release:

- Integrate the multi-tunnel packet router into one shared Android VPN.
- Allocate collision-free tunnel addresses and coordinate global forwarding settings.
- Implement server leases, reconciliation and independent reconnect/backoff.
- Test actual packet transfer against Linux/OpenSSH and on Android, including DNS,
  ProxyJump, cancellation, network changes and concurrent clients.

Do not treat a successful APK build as evidence of a working VPN.

### Server requirements

The SSH server must support OpenSSH point-to-point tunnel forwarding:

    PermitTunnel yes

The SSH login must already have the permissions needed to configure its TUN,
routes, forwarding sysctls and nftables. The app invokes no privilege escalation.
The server needs /dev/net/tun, iproute2 and nftables. SSH exec channels must be
allowed; ForceCommand or authorized_keys restrictions can prevent setup.
Existing firewall forwarding policies must permit the traffic; adding an accept
rule in an application table cannot override a drop in another base chain.

IPv6 internet access requires an appropriate prefix routed to the server and
configured in the profile. An on-link provider /64 is not automatically a delegated
prefix for VPN clients; upstream routing or an explicitly designed NDP setup is needed.
The current draft does not configure proxy NDP.

Only use an isolated test server for development. In particular, global forwarding
restoration and fixed IPv4 tunnel addresses are not yet safe for concurrent clients.

### Server plan confirmation

For VPN and SOCKS5 + VPN, SSH authentication is followed by a server plan dialog,
before the OpenSSH TUN channel is opened or server networking is changed. A
read-only route probe may run to discover the IPv4 egress interface. Review the
generated setup and cleanup commands; edit the egress interface and the switches
for IPv4/IPv6 forwarding, IPv4 masquerade, outbound accept and return accept.
The command preview updates immediately. These switches control only the app's
own configuration; they do not disable or override existing firewall rules.

**Apply and connect** saves the selected options to the host profile and continues
the waiting connection. **Cancel** closes the SSH connection without applying the
server plan. Select **Больше не спрашивать для этого хоста** before applying to
reuse the saved settings automatically for this host, including reconnects. Cancel
does not save this preference. Re-enable **Показывать настройки сервера перед
подключением** in the host editor to restore the dialog. Existing profiles ask by
default. Automatic use still logs the full plan and server acknowledgements.
SOCKS5-only connections do not show this dialog.

At INFO verbosity the log distinguishes **ПЛАН** (approved commands),
**ПРИМЕНЕНО** (steps acknowledged by the server after successful execution),
and cleanup confirmation/failure. If SSH is unavailable during cleanup, the log
reports that cleanup was not confirmed. A planned rule is not proof that the server
applied it. NAT and accept switches default to the previous behavior for profiles
saved by earlier versions.

Manual verification: cancel a plan and check that no app table was created;
change the interface/NAT options, connect and compare the preview and log with
`nft list table inet <table-from-plan>`; disconnect and check cleanup; reconnect
and verify the saved choices. Repeat with IPv4, IPv6 and combined SOCKS5 + VPN.

## License

Licensed under the [MIT License](LICENSE). Third-party dependencies retain their own licenses.
