package ru.birdiecode.ssh2socks4android;

import android.util.Base64;

import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.UserInfo;

import java.security.MessageDigest;

/** Captures unknown keys during KEX and accepts only an explicitly pinned fingerprint. */
final class PinnedHostKeyRepository implements HostKeyRepository {
    private final String pinnedFingerprint;
    private volatile String offeredFingerprint = "";

    PinnedHostKeyRepository(String pinnedFingerprint) {
        this.pinnedFingerprint = pinnedFingerprint == null ? "" : pinnedFingerprint;
    }

    String getOfferedFingerprint() {
        return offeredFingerprint;
    }

    @Override public int check(String host, byte[] key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key);
            offeredFingerprint = "SHA256:" + Base64.encodeToString(digest, Base64.NO_PADDING | Base64.NO_WRAP);
        } catch (Exception e) {
            offeredFingerprint = "";
            return NOT_VERIFIABLE;
        }
        if (pinnedFingerprint.isEmpty()) return NOT_INCLUDED;
        return pinnedFingerprint.equals(offeredFingerprint) ? OK : CHANGED;
    }

    @Override public void add(HostKey hostkey, UserInfo userinfo) {}
    @Override public void remove(String host, String type) {}
    @Override public void remove(String host, String type, byte[] key) {}
    @Override public HostKey[] getHostKey() { return new HostKey[0]; }
    @Override public HostKey[] getHostKey(String host, String type) { return new HostKey[0]; }
    @Override public String getKnownHostsRepositoryID() { return "SSH2SOCKS pinned hosts"; }
}
