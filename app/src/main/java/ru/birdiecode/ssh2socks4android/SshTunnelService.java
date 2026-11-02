package ru.birdiecode.ssh2socks4android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Base64;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import java.security.MessageDigest;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class SshTunnelService extends Service {
    static final String ACTION_CONNECT = "ru.birdiecode.ssh2socks4android.CONNECT";
    static final String ACTION_TRUST = "ru.birdiecode.ssh2socks4android.TRUST";
    static final String ACTION_STOP = "ru.birdiecode.ssh2socks4android.STOP";
    static final String EXTRA_PROFILE_ID = "profile_id";

    private static final String CHANNEL_ID = "ssh_tunnel";
    private static final int NOTIFICATION_ID = 41;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private volatile Session activeSession;
    private volatile Session activeJumpSession;
    private volatile Socks5Proxy activeProxy;
    private volatile String activeProfileId = "";

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startInForeground("SSH tunnel", "Preparing connection…");
        String action = intent == null ? ACTION_STOP : intent.getAction();
        String profileId = intent == null ? "" : intent.getStringExtra(EXTRA_PROFILE_ID);

        if (ACTION_CONNECT.equals(action)) {
            worker.execute(() -> connect(profileId));
        } else if (ACTION_TRUST.equals(action)) {
            worker.execute(() -> trustAndConnect(profileId));
        } else {
            worker.execute(this::disconnect);
        }
        return START_NOT_STICKY;
    }

    private void trustAndConnect(String profileId) {
        Profile profile = ProfileStore.get(this, profileId);
        String pending = ProfileStore.pendingFingerprint(this);
        if (profile == null || pending.isEmpty() || !profileId.equals(ProfileStore.statusProfile(this))) {
            fail(profileId, "No pending host key confirmation");
            return;
        }
        boolean jumpKey = pending.startsWith("JUMP:");
        String fingerprint = pending.startsWith("JUMP:") || pending.startsWith("TARGET:")
                ? pending.substring(pending.indexOf(':') + 1) : pending;
        if (jumpKey) profile.jumpFingerprint = fingerprint;
        else profile.hostFingerprint = fingerprint;
        ProfileStore.save(this, profile);
        ProfileStore.setPendingFingerprint(this, "");
        connect(profileId);
    }

    private void connect(String profileId) {
        closeActiveSession();
        Profile profile = ProfileStore.get(this, profileId);
        if (profile == null) {
            fail(profileId, "Connection profile was not found");
            return;
        }

        SshKey targetKey = profile.keyId == null || profile.keyId.isEmpty()
                ? null : SshKeyStore.get(this, profile.keyId);
        boolean legacyTargetKey = targetKey == null && (profile.keyId == null || profile.keyId.isEmpty())
                && profile.encryptedKey != null && !profile.encryptedKey.isEmpty();
        boolean hasTargetKey = targetKey != null || legacyTargetKey;
        boolean hasTargetPassword = profile.encryptedPassword != null && !profile.encryptedPassword.isEmpty();
        if (!hasTargetKey && !hasTargetPassword) {
            fail(profileId, "Add an SSH password or select a private key");
            return;
        }

        boolean useJump = profile.jumpHost != null && !profile.jumpHost.trim().isEmpty();
        SshKey jumpKey = profile.jumpKeyId == null || profile.jumpKeyId.isEmpty()
                ? null : SshKeyStore.get(this, profile.jumpKeyId);
        boolean hasJumpPassword = profile.encryptedJumpPassword != null && !profile.encryptedJumpPassword.isEmpty();
        if (useJump && (profile.jumpUsername == null || profile.jumpUsername.trim().isEmpty())) {
            fail(profileId, "Enter a username for the jump server");
            return;
        }
        if (useJump && jumpKey == null && !hasJumpPassword) {
            fail(profileId, "Add a password or select a key for the jump server");
            return;
        }

        activeProfileId = profile.id;
        ProfileStore.setStatus(this, profile.id, "CONNECTING",
                "Connecting to " + profile.host + (useJump ? " via " + profile.jumpHost : ""));
        updateNotification("Connecting", profile.username + "@" + profile.host
                + (useJump ? " via " + profile.jumpHost : ""));

        Session jumpCandidate = null;
        Session targetCandidate = null;
        try {
            if (useJump) {
                JSch jumpJsch = new JSch();
                addAllVaultKeys(jumpJsch);
                Session jumpSession = jumpJsch.getSession(
                        profile.jumpUsername, profile.jumpHost, profile.jumpPort);
                jumpCandidate = jumpSession;
                if (hasJumpPassword) jumpSession.setPassword(KeyVault.decrypt(profile.encryptedJumpPassword));
                configureAuthentication(jumpSession);
                jumpSession.setConfig("StrictHostKeyChecking", "no");
                jumpSession.connect(20_000);

                String jumpFingerprint = fingerprint(jumpSession);
                if (profile.jumpFingerprint == null || profile.jumpFingerprint.isEmpty()) {
                    jumpSession.disconnect();
                    requestTrust(profile.id, "JUMP:" + jumpFingerprint);
                    return;
                }
                if (!profile.jumpFingerprint.equals(jumpFingerprint)) {
                    jumpSession.disconnect();
                    fail(profile.id, "Jump server host key changed. Verify it before updating the saved fingerprint.");
                    return;
                }
            }

            JSch targetJsch = new JSch();
            addAllVaultKeys(targetJsch);
            Session targetSession = targetJsch.getSession(profile.username, profile.host, profile.sshPort);
            targetCandidate = targetSession;
            if (hasTargetPassword) targetSession.setPassword(KeyVault.decrypt(profile.encryptedPassword));
            configureAuthentication(targetSession);
            if (useJump) targetSession.setProxy(new SshJumpProxy(jumpCandidate));
            targetSession.setConfig("StrictHostKeyChecking", "no");
            targetSession.connect(20_000);

            String targetFingerprint = fingerprint(targetSession);
            if (profile.hostFingerprint == null || profile.hostFingerprint.isEmpty()) {
                targetSession.disconnect();
                if (jumpCandidate != null) jumpCandidate.disconnect();
                requestTrust(profile.id, "TARGET:" + targetFingerprint);
                return;
            }
            if (!profile.hostFingerprint.equals(targetFingerprint)) {
                targetSession.disconnect();
                if (jumpCandidate != null) jumpCandidate.disconnect();
                fail(profile.id, "SSH host key changed. Verify it before updating the saved fingerprint.");
                return;
            }

            Socks5Proxy proxy = new Socks5Proxy(targetSession, profile.localPort);
            proxy.start();
            activeSession = targetSession;
            activeJumpSession = jumpCandidate;
            activeProxy = proxy;
            ProfileStore.setStatus(this, profile.id, "CONNECTED",
                    "SOCKS5 listening on 127.0.0.1:" + profile.localPort);
            updateNotification("SSH tunnel connected",
                    "SOCKS5 127.0.0.1:" + profile.localPort + " via " + profile.host);
        } catch (Exception e) {
            if (targetCandidate != null) {
                try { targetCandidate.disconnect(); } catch (Exception ignored) {}
            }
            if (jumpCandidate != null) {
                try { jumpCandidate.disconnect(); } catch (Exception ignored) {}
            }
            fail(profile.id, readableMessage(e));
        }
    }

    private void addAllVaultKeys(JSch jsch) throws Exception {
        for (SshKey key : SshKeyStore.all(this)) {
            byte[] privateKey = KeyVault.decrypt(key.encryptedPrivateKey);
            byte[] passphrase = key.encryptedPassphrase == null || key.encryptedPassphrase.isEmpty()
                    ? null : KeyVault.decrypt(key.encryptedPassphrase);
            jsch.addIdentity("vault-" + key.id, privateKey, null, passphrase);
        }
    }

    private void addLegacyKey(JSch jsch, Profile profile) throws Exception {
        byte[] privateKey = KeyVault.decrypt(profile.encryptedKey);
        byte[] passphrase = profile.encryptedPassphrase == null || profile.encryptedPassphrase.isEmpty()
                ? null : KeyVault.decrypt(profile.encryptedPassphrase);
        jsch.addIdentity("legacy-" + profile.id, privateKey, null, passphrase);
    }

    private void configureAuthentication(Session session) {
        session.setConfig("PreferredAuthentications", "publickey,password");
    }

    private String fingerprint(Session session) throws Exception {
        byte[] key = Base64.decode(session.getHostKey().getKey(), Base64.DEFAULT);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(key);
        return "SHA256:" + Base64.encodeToString(digest, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private void requestTrust(String profileId, String taggedFingerprint) {
        ProfileStore.setPendingFingerprint(this, taggedFingerprint);
        ProfileStore.setStatus(this, profileId, "NEEDS_TRUST", taggedFingerprint);
        updateNotification("Verify SSH server", "Open the app to review its host fingerprint");
        stopForeground(true);
        stopSelf();
    }

    private void disconnect() {
        closeActiveSession();
        ProfileStore.setPendingFingerprint(this, "");
        ProfileStore.setStatus(this, activeProfileId, "IDLE", "Disconnected");
        stopForeground(true);
        stopSelf();
    }

    private void closeActiveSession() {
        Socks5Proxy proxy = activeProxy;
        activeProxy = null;
        if (proxy != null) proxy.stop();

        Session target = activeSession;
        activeSession = null;
        if (target != null) {
            try { target.disconnect(); } catch (Exception ignored) {}
        }

        Session jump = activeJumpSession;
        activeJumpSession = null;
        if (jump != null) {
            try { jump.disconnect(); } catch (Exception ignored) {}
        }
    }

    private void fail(String profileId, String message) {
        closeActiveSession();
        ProfileStore.setStatus(this, profileId, "ERROR", message);
        updateNotification("SSH tunnel stopped", message);
        stopForeground(true);
        stopSelf();
    }

    private String readableMessage(Exception e) {
        String message = e.getMessage();
        return message == null || message.trim().isEmpty()
                ? e.getClass().getSimpleName() : message;
    }

    private void startInForeground(String title, String text) {
        Notification notification = buildNotification(title, text);
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private void updateNotification(String title, String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) manager.notify(NOTIFICATION_ID, buildNotification(title, text));
    }

    private Notification buildNotification(String title, String text) {
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent contentIntent = PendingIntent.getActivity(
                this, 0, open, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setContentIntent(contentIntent)
                .setOngoing("SSH tunnel connected".equals(title) || "Connecting".equals(title))
                .build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "SSH tunnel", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Shows the state of the SSH SOCKS5 tunnel");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    @Override
    public void onDestroy() {
        closeActiveSession();
        worker.shutdownNow();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
