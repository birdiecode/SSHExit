package ru.birdiecode.ssh2socks4android;

import java.util.UUID;

/** A reusable SSH host. Hosts may be targets or intermediate ProxyJump nodes. */
final class Profile {
    String id = UUID.randomUUID().toString();
    String name = "";
    String host = "";
    int sshPort = 22;
    String username = "";
    int localPort = 1080;

    // VPN settings; profiles created before VPN support retain SOCKS5 as their mode.
    String connectionMode = "SOCKS5";
    boolean vpnIpv4 = true;
    boolean vpnIpv6 = false;
    int vpnMtu = 1400;
    String vpnDnsServers = "1.1.1.1";
    boolean vpnFullTunnel = true;
    String vpnRoutes = "";
    int vpnRoutePriority = 0;
    boolean vpnPrimary = false;
    boolean vpnFailover = false;
    boolean vpnAutoReconnect = true;
    String vpnExternalInterface = "";

    // New graph-based routing. Empty means direct connection.
    String jumpProfileId = "";

    // Encrypted per-host password and pinned SSH host key.
    String encryptedPassword = "";
    String hostFingerprint = "";
    // Last observed host key when it did not match the trusted pin.
    String observedFingerprint = "";

    // Legacy fields retained for migration from the first released schema.
    String keyId = "";
    String encryptedKey = "";
    String encryptedPassphrase = "";
    String jumpHost = "";
    int jumpPort = 22;
    String jumpUsername = "";
    String encryptedJumpPassword = "";
    String jumpKeyId = "";
    String jumpFingerprint = "";

    Profile() {}

    Profile(String name, String host, int sshPort, String username, int localPort) {
        this.name = name;
        this.host = host;
        this.sshPort = sshPort;
        this.username = username;
        this.localPort = localPort;
    }
}
