package ru.birdiecode.ssh2socks4android;

import java.util.UUID;

final class SshKey {
    String id = UUID.randomUUID().toString();
    String name = "";
    String encryptedPrivateKey = "";
    String encryptedPassphrase = "";

    SshKey() {}

    SshKey(String name, String encryptedPrivateKey, String encryptedPassphrase) {
        this.name = name;
        this.encryptedPrivateKey = encryptedPrivateKey;
        this.encryptedPassphrase = encryptedPassphrase;
    }
}
