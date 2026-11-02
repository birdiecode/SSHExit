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
        profile.hostFingerprint = pending;
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
        if (profile.encryptedKey == null || profile.encryptedKey.isEmpty()) {
            fail(profileId, "Import an SSH private key first");
            return;
        }

        activeProfileId = profile.id;
        ProfileStore.setStatus(this, profile.id, "CONNECTING", "Connecting to " + profile.host);
        updateNotification("Connecting", profile.username + "@" + profile.host);

        try {
            byte[] privateKey = KeyVault.decrypt(profile.encryptedKey);
            byte[] passphrase = profile.encryptedPassphrase == null || profile.encryptedPassphrase.isEmpty()
                    ? null : KeyVault.decrypt(profile.encryptedPassphrase);

            JSch jsch = new JSch();
            jsch.addIdentity("profile-" + profile.id, privateKey, null, passphrase);
            Session session = jsch.getSession(profile.username, profile.host, profile.sshPort);
            session.setConfig("PreferredAuthentications", "publickey");
            // The key is inspected below before any tunnel channel is created. It is pinned only
            // after the user confirms the displayed fingerprint, and compared on every reconnect.
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect(20_000);

            String fingerprint = sha256Fingerprint(session.getHostKey().getKey());
            if (profile.hostFingerprint == null || profile.hostFingerprint.isEmpty()) {
                session.disconnect();
                ProfileStore.setPendingFingerprint(this, fingerprint);
                ProfileStore.setStatus(this, profile.id, "NEEDS_TRUST", fingerprint);
                updateNotification("Verify SSH server", "Open the app to review its host fingerprint");
                stopForeground(true);
                stopSelf();
                return;
            }
            if (!profile.hostFingerprint.equals(fingerprint)) {
                session.disconnect();
                fail(profile.id, "SSH host key changed. Verify it before updating the saved fingerprint.");
                return;
            }

            session.setPortForwardingD(profile.localPort);
            activeSession = session;
            ProfileStore.setStatus(this, profile.id, "CONNECTED",
                    "SOCKS5 listening on 127.0.0.1:" + profile.localPort);
            updateNotification("SSH tunnel connected",
                    "SOCKS5 127.0.0.1:" + profile.localPort + " via " + profile.host);
        } catch (Exception e) {
            fail(profile.id, readableMessage(e));
        }
    }

    private void disconnect() {
        closeActiveSession();
        ProfileStore.setPendingFingerprint(this, "");
        ProfileStore.setStatus(this, activeProfileId, "IDLE", "Disconnected");
        stopForeground(true);
        stopSelf();
    }

    private void closeActiveSession() {
        Session session = activeSession;
        activeSession = null;
        if (session != null) {
            try { session.disconnect(); } catch (Exception ignored) {}
        }
    }

    private void fail(String profileId, String message) {
        closeActiveSession();
        ProfileStore.setStatus(this, profileId, "ERROR", message);
        updateNotification("SSH tunnel stopped", message);
        stopForeground(true);
        stopSelf();
    }

    private String sha256Fingerprint(byte[] hostKey) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(hostKey);
        return "SHA256:" + Base64.encodeToString(digest, Base64.NO_PADDING | Base64.NO_WRAP);
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
