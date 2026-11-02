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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class SshTunnelService extends Service {
    static final String ACTION_CONNECT = "ru.birdiecode.ssh2socks4android.CONNECT";
    static final String ACTION_TRUST = "ru.birdiecode.ssh2socks4android.TRUST";
    static final String ACTION_STOP = "ru.birdiecode.ssh2socks4android.STOP";
    static final String EXTRA_PROFILE_ID = "profile_id";
    static final String ACTION_PASSWORD = "ru.birdiecode.ssh2socks4android.PASSWORD";
    static final String EXTRA_NODE_ID = "node_id";
    static final String EXTRA_PASSWORD = "password";

    private static final String CHANNEL_ID = "ssh_tunnel";
    private static final int NOTIFICATION_ID = 41;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final List<Session> activeSessions = Collections.synchronizedList(new ArrayList<>());
    private volatile Session activeSession;
    private volatile Socks5Proxy activeProxy;
    private volatile String activeProfileId = "";
    private final Map<String, String> pendingPasswords = new HashMap<>();

    @Override public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        startInForeground("SSH tunnel", "Preparing connection…");
        String action = intent == null ? ACTION_STOP : intent.getAction();
        String profileId = intent == null ? "" : intent.getStringExtra(EXTRA_PROFILE_ID);
        if (ACTION_CONNECT.equals(action)) worker.execute(() -> connect(profileId));
        else if (ACTION_TRUST.equals(action)) worker.execute(() -> trustAndConnect(profileId));
        else if (ACTION_PASSWORD.equals(action)) {
            String nodeId = intent == null ? "" : intent.getStringExtra(EXTRA_NODE_ID);
            String password = intent == null ? "" : intent.getStringExtra(EXTRA_PASSWORD);
            worker.execute(() -> {
                if (nodeId == null || nodeId.isEmpty() || password == null || password.isEmpty()) {
                    fail(profileId, "Пароль не задан");
                    return;
                }
                pendingPasswords.put(nodeId, password);
                connect(profileId);
            });
        } else worker.execute(this::disconnect);
        return START_NOT_STICKY;
    }

    private void trustAndConnect(String targetId) {
        String pending = ProfileStore.pendingFingerprint(this);
        if (pending == null || !pending.startsWith("NODE:")) {
            fail(targetId, "No pending host key confirmation");
            return;
        }
        int split = pending.indexOf(':', 5);
        if (split < 0) {
            fail(targetId, "Invalid pending host key confirmation");
            return;
        }
        String nodeId = pending.substring(5, split);
        String fingerprint = pending.substring(split + 1);
        Profile node = ProfileStore.get(this, nodeId);
        if (node == null || !targetId.equals(ProfileStore.statusProfile(this))) {
            fail(targetId, "The host awaiting confirmation no longer exists");
            return;
        }
        node.hostFingerprint = fingerprint;
        node.observedFingerprint = "";
        ProfileStore.save(this, node);
        ProfileStore.setPendingFingerprint(this, "");
        connect(targetId);
    }

    private void connect(String targetId) {
        closeActiveSession();
        Profile target = ProfileStore.get(this, targetId);
        if (target == null) { fail(targetId, "Connection profile was not found"); return; }

        List<Profile> chain;
        try {
            chain = resolveChain(target);
        } catch (Exception e) {
            fail(targetId, e.getMessage());
            return;
        }

        activeProfileId = targetId;
        ProfileStore.setStatus(this, targetId, "CONNECTING",
                "Connecting through " + chainLabel(chain));
        updateNotification("Connecting", chainLabel(chain));

        Session previous = null;
        try {
            for (Profile node : chain) {
                JSch jsch = new JSch();
                addAllVaultKeys(jsch);
                PinnedHostKeyRepository pinning = new PinnedHostKeyRepository(node.hostFingerprint);
                jsch.setHostKeyRepository(pinning);
                Session session = jsch.getSession(node.username, node.host, node.sshPort);
                session.setConfig("StrictHostKeyChecking", "yes");
                String promptedPassword = pendingPasswords.get(node.id);
                boolean hasSavedPassword = node.encryptedPassword != null && !node.encryptedPassword.isEmpty();
                if (promptedPassword != null) {
                    session.setPassword(promptedPassword.getBytes(StandardCharsets.UTF_8));
                    session.setConfig("PreferredAuthentications", "password");
                } else if (hasSavedPassword) {
                    session.setPassword(KeyVault.decrypt(node.encryptedPassword));
                    session.setConfig("PreferredAuthentications", "publickey,password");
                } else {
                    session.setConfig("PreferredAuthentications", "publickey");
                }
                if (previous != null) session.setProxy(new SshJumpProxy(previous));
                try {
                    session.connect(20_000);
                } catch (Exception e) {
                    try { session.disconnect(); } catch (Exception ignored) {}
                    String offered = pinning.getOfferedFingerprint();
                    if (!offered.isEmpty() && (node.hostFingerprint == null || node.hostFingerprint.isEmpty())) {
                        requestTrust(targetId, node.id, offered);
                        return;
                    }
                    if (!offered.isEmpty()) {
                        node.observedFingerprint = offered;
                        ProfileStore.save(this, node);
                        throw new NodeException(node,
                                "Проверка fingerprint не пройдена. Доверенный: "
                                        + node.hostFingerprint + " · получен: " + offered, null);
                    }
                    if (isAuthenticationFailure(e)) {
                        if (promptedPassword != null) {
                            pendingPasswords.remove(node.id);
                            throw new NodeException(node, "Пароль отклонён", null);
                        }
                        requestPassword(targetId, node);
                        return;
                    }
                    throw new NodeException(node, "SSH connection failed", e);
                }
                activeSessions.add(session);
                if (node.observedFingerprint != null && !node.observedFingerprint.isEmpty()) {
                    node.observedFingerprint = "";
                    ProfileStore.save(this, node);
                }
                if (promptedPassword != null) {
                    if (!hasSavedPassword) {
                        node.encryptedPassword = KeyVault.encrypt(promptedPassword.getBytes(StandardCharsets.UTF_8));
                        ProfileStore.save(this, node);
                    }
                    pendingPasswords.remove(node.id);
                }
                previous = session;
            }

            activeSession = previous;
            Socks5Proxy proxy = new Socks5Proxy(previous, target.localPort);
            proxy.start();
            activeProxy = proxy;
            ProfileStore.setStatus(this, targetId, "CONNECTED",
                    "SOCKS5 listening on 127.0.0.1:" + target.localPort);
            updateNotification("SSH tunnel connected",
                    "SOCKS5 127.0.0.1:" + target.localPort + " via " + chainLabel(chain));
        } catch (Exception e) {
            String message = e instanceof NodeException
                    ? ((NodeException) e).getMessage()
                    : readableMessage(e);
            closeActiveSession();
            fail(targetId, message);
        }
    }

    private List<Profile> resolveChain(Profile target) throws Exception {
        ArrayList<Profile> reversed = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Profile node = target;
        while (node != null) {
            if (!seen.add(node.id)) throw new IllegalArgumentException("ProxyJump cycle detected at " + display(node));
            reversed.add(node);
            String jumpId = node.jumpProfileId == null ? "" : node.jumpProfileId;
            if (jumpId.isEmpty()) break;
            node = ProfileStore.get(this, jumpId);
            if (node == null) throw new IllegalArgumentException("ProxyJump host for " + display(reversed.get(reversed.size() - 1)) + " was deleted");
            if (reversed.size() > ProfileStore.all(this).size()) throw new IllegalArgumentException("ProxyJump chain is invalid");
        }
        Collections.reverse(reversed);
        return reversed;
    }

    private String chainLabel(List<Profile> chain) {
        ArrayList<String> labels = new ArrayList<>();
        for (Profile node : chain) labels.add(display(node));
        return android.text.TextUtils.join(" → ", labels);
    }

    private String display(Profile node) {
        return (node.name == null || node.name.trim().isEmpty() ? node.host : node.name)
                + " (" + node.username + "@" + node.host + ")";
    }

    private boolean isAuthenticationFailure(Exception error) {
        String message = error.getMessage();
        if (message == null) return false;
        String lower = message.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("auth fail") || lower.contains("authentication failed")
                || lower.contains("auth cancel") || lower.contains("no more authentication methods");
    }

    private void requestPassword(String targetId, Profile node) {
        activeProfileId = targetId;
        closeActiveSession();
        ProfileStore.setStatus(this, targetId, "NEEDS_PASSWORD", "NODE:" + node.id);
        updateNotification("SSH password required", "Enter password for " + node.username + "@" + node.host);
        // Keep the foreground service alive while the activity asks for the password.
    }

    private void addAllVaultKeys(JSch jsch) {
        for (SshKey key : SshKeyStore.all(this)) {
            try {
                byte[] privateKey = KeyVault.decrypt(key.encryptedPrivateKey);
                byte[] passphrase = key.encryptedPassphrase == null || key.encryptedPassphrase.isEmpty()
                        ? null : KeyVault.decrypt(key.encryptedPassphrase);
                jsch.addIdentity("vault-" + key.id, privateKey, null, passphrase);
            } catch (Exception ignored) {
                // An unreadable or unsupported key must not prevent trying other identities.
            }
        }
    }

    private void requestTrust(String targetId, String nodeId, String fingerprint) {
        ProfileStore.setPendingFingerprint(this, "NODE:" + nodeId + ":" + fingerprint);
        ProfileStore.setStatus(this, targetId, "NEEDS_TRUST", "NODE:" + nodeId + ":" + fingerprint);
        updateNotification("Verify SSH server", "Open the app to review its host fingerprint");
        closeActiveSession();
        stopForeground(true);
        stopSelf();
    }

    private void disconnect() {
        closeActiveSession();
        pendingPasswords.clear();
        ProfileStore.setPendingFingerprint(this, "");
        if (!activeProfileId.isEmpty()) ProfileStore.setStatus(this, activeProfileId, "IDLE", "Disconnected");
        stopForeground(true);
        stopSelf();
    }

    private void closeActiveSession() {
        Socks5Proxy proxy = activeProxy;
        activeProxy = null;
        if (proxy != null) proxy.stop();
        activeSession = null;
        synchronized (activeSessions) {
            for (int i = activeSessions.size() - 1; i >= 0; i--) {
                try { activeSessions.get(i).disconnect(); } catch (Exception ignored) {}
            }
            activeSessions.clear();
        }
    }

    private void fail(String profileId, String message) {
        closeActiveSession();
        pendingPasswords.clear();
        ProfileStore.setStatus(this, profileId, "ERROR", message == null ? "Connection failed" : message);
        updateNotification("SSH tunnel stopped", message == null ? "Connection failed" : message);
        stopForeground(true);
        stopSelf();
    }

    private String readableMessage(Exception e) {
        String message = e.getMessage();
        return message == null || message.trim().isEmpty() ? e.getClass().getSimpleName() : message;
    }

    private void startInForeground(String title, String text) {
        Notification notification = buildNotification(title, text);
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        } else startForeground(NOTIFICATION_ID, notification);
    }

    private void updateNotification(String title, String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) manager.notify(NOTIFICATION_ID, buildNotification(title, text));
    }

    private Notification buildNotification(String title, String text) {
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent contentIntent = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Intent stop = new Intent(this, SshTunnelService.class);
        stop.setAction(ACTION_STOP);
        stop.putExtra(EXTRA_PROFILE_ID, activeProfileId);
        PendingIntent stopIntent = PendingIntent.getService(this, 1, stop,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder builder = new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setContentTitle(title).setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setContentIntent(contentIntent)
                .setOngoing("SSH tunnel connected".equals(title) || "Connecting".equals(title));
        if ("SSH tunnel connected".equals(title) || "Connecting".equals(title)) {
            builder.addAction(new Notification.Action.Builder(null, "Disconnect", stopIntent).build());
        }
        return builder.build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "SSH tunnel", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Shows the state of the SSH SOCKS5 tunnel");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    @Override public void onDestroy() {
        closeActiveSession();
        worker.shutdownNow();
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    private static final class NodeException extends Exception {
        NodeException(Profile node, String reason, Throwable cause) {
            super((node.name == null || node.name.trim().isEmpty() ? node.host : node.name)
                    + " (" + node.username + "@" + node.host + "): " + reason
                    + (cause == null || cause.getMessage() == null ? "" : " — " + cause.getMessage()), cause);
        }
    }
}
