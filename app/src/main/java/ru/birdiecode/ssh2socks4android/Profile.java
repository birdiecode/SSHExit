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

    // New graph-based routing. Empty means direct connection.
    String jumpProfileId = "";

    // Encrypted per-host password and pinned SSH host key.
    String encryptedPassword = "";
    String hostFingerprint = "";

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
