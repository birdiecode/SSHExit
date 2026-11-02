package ru.birdiecode.ssh2socks4android;

import java.util.UUID;

final class Profile {
    String id = UUID.randomUUID().toString();
    String name = "";
    String host = "";
    int sshPort = 22;
    String username = "";
    int localPort = 1080;
    String encryptedKey = "";
    String encryptedPassword = "";
    String encryptedPassphrase = "";
    String hostFingerprint = "";

    Profile() {}

    Profile(String name, String host, int sshPort, String username, int localPort) {
        this.name = name;
        this.host = host;
        this.sshPort = sshPort;
        this.username = username;
        this.localPort = localPort;
    }
}
