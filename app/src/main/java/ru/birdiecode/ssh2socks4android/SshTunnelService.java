package ru.birdiecode.ssh2socks4android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Base64;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.OpenSshTunChannel;
import com.jcraft.jsch.SocketFactory;
import com.jcraft.jsch.Session;

import java.security.MessageDigest;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Random;
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

public final class SshTunnelService extends VpnService {
    static final String ACTION_CONNECT = "host.birdiecode.sshexit.CONNECT";
    static final String ACTION_TRUST = "host.birdiecode.sshexit.TRUST";
    static final String ACTION_STOP = "host.birdiecode.sshexit.STOP";
    static final String EXTRA_PROFILE_ID = "profile_id";
    static final String ACTION_SERVER_CONFIG = "host.birdiecode.sshexit.SERVER_CONFIG";
    static final String ACTION_PASSWORD = "host.birdiecode.sshexit.PASSWORD";
    static final String EXTRA_NODE_ID = "node_id";
    static final String EXTRA_PASSWORD = "password";

    private static final String CHANNEL_ID = "ssh_tunnel";
    private static final int NOTIFICATION_ID = 41;
    private static final String ACTION_REQUIRED_CHANNEL = "ssh_server_action";
    private static final int ACTION_REQUIRED_ID = 42;
    private static volatile boolean uiVisible;
    private static java.lang.ref.WeakReference<SshTunnelService> runningService =
            new java.lang.ref.WeakReference<>(null);
    private final Map<String, String> notifiedServerRequests = new HashMap<>();

    // Activity visibility changes never start a service or initiate a connection.
    static void setUiVisible(boolean visible) {
        uiVisible = visible;
        SshTunnelService service = runningService.get();
        if (service != null) service.main.post(service::refreshNotification);
    }

    private final java.util.concurrent.ConcurrentHashMap<String, SshConnection> connections =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final android.os.Handler main = new android.os.Handler(android.os.Looper.getMainLooper());
    private SshConnection vpnOwner;
    private boolean destroyed;
    private final ExecutorService cleanup = Executors.newFixedThreadPool(4);
    private final SshConnection.Host connectionHost = new SshConnection.Host() {
        @Override public void changed(SshConnection connection) { main.post(() -> refreshNotification()); }
        @Override public void claimVpn(SshConnection connection) { claimVpnOwner(connection); }
        @Override public void releaseVpn(SshConnection connection) { releaseVpnOwner(connection); }
        @Override public void cleanup(Runnable action) { cleanup.execute(action); }
        @Override public boolean isCurrent(SshConnection connection) {
            return connections.get(connection.profileId()) == connection;
        }
    };

    @Override public void onCreate() {
        super.onCreate();
        ProfileStore.resetConnectionStatuses(this);
        createNotificationChannel();
        runningService = new java.lang.ref.WeakReference<>(this);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        startInForeground("SSH tunnel", "Подготовка подключения");
        String action = intent == null ? ACTION_STOP : intent.getAction();
        String id = intent == null ? "" : intent.getStringExtra(EXTRA_PROFILE_ID);
        if (id == null) id = "";
        if (ACTION_STOP.equals(action)) {
            if (id.isEmpty()) {
                for (SshConnection c : connections.values()) c.shutdown();
            } else {
                SshConnection c = connections.get(id);
                if (c != null) c.shutdown();
            }
            refreshNotification();
            return START_NOT_STICKY;
        }
        if (id.isEmpty()) { refreshNotification(); return START_NOT_STICKY; }
        SshConnection connection = connections.get(id);
        if (ACTION_CONNECT.equals(action)) {
            if (connection == null || !connection.isLive()) {
                if (connection != null) connection.shutdown();
                connection = new SshConnection(this, connectionHost, id);
                connections.put(id, connection);
                SshConnection next = connection;
                String target = id;
                next.execute(() -> next.connect(target));
            }
        } else if (connection != null) {
            SshConnection current = connection;
            String target = id;
            if (ACTION_TRUST.equals(action)) current.execute(() -> current.trustAndConnect(target));
            else if (ACTION_SERVER_CONFIG.equals(action)) current.execute(() -> current.applyServerPlan(intent));
            else if (ACTION_PASSWORD.equals(action)) {
                String node = intent.getStringExtra(EXTRA_NODE_ID);
                String password = intent.getStringExtra(EXTRA_PASSWORD);
                current.execute(() -> current.password(node, password));
            }
        }
        refreshNotification();
        return START_NOT_STICKY;
    }

    // A shared packet router replaces this single-VPN reservation in the next stage.
    // Explicit rejection protects existing tunnels while lifecycle isolation is introduced.
    private synchronized void claimVpnOwner(SshConnection connection) {
        long deadline = System.currentTimeMillis() + 20000;
        while (vpnOwner != null && vpnOwner != connection && !vpnOwner.isLive()
                && System.currentTimeMillis() < deadline) {
            try { wait(100); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("Подключение отменено"); }
        }
        if (vpnOwner != null && vpnOwner != connection)
            throw new IllegalStateException("В этой сборке пока поддерживается один VPN и несколько SOCKS5");
        vpnOwner = connection;
    }
    private synchronized void releaseVpnOwner(SshConnection connection) {
        if (vpnOwner == connection) { vpnOwner = null; notifyAll(); }
    }

    private void refreshNotification() {
        if (destroyed) return;
        refreshServerActionNotifications();
        int connected = 0, pending = 0;
        for (SshConnection c : connections.values()) {
            if (!c.isLive()) continue;
            if ("CONNECTED".equals(c.state)) connected++; else pending++;
        }
        if (connected + pending == 0) {
            stopForeground(true);
            stopSelf();
        } else updateNotification("SSH tunnel connected",
                "Подключено: " + connected + " · В процессе: " + pending);
    }

    private void refreshServerActionNotifications() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) return;
        Set<String> waiting = new HashSet<>();
        for (SshConnection connection : connections.values()) {
            String id = connection.profileId();
            if (uiVisible || !connection.isLive() || !"NEEDS_SERVER_CONFIG".equals(connection.state)) continue;
            Profile profile = ProfileStore.get(this, id);
            if (profile == null || profile.serverSkipConfirmation) continue;
            String request = ProfileStore.statusDetail(this, id);
            if (request == null || request.isEmpty()) continue;
            waiting.add(id);
            if (request.equals(notifiedServerRequests.get(id))) continue;
            if (!manager.areNotificationsEnabled()
                    || (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(
                    android.Manifest.permission.POST_NOTIFICATIONS)
                    != android.content.pm.PackageManager.PERMISSION_GRANTED)) continue;
            Intent open = new Intent(this, MainActivity.class)
                    .setAction("host.birdiecode.sshexit.SERVER_CONFIG." + id)
                    .putExtra(EXTRA_PROFILE_ID, id)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            PendingIntent content = PendingIntent.getActivity(this, 0, open,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            String name = profile.name == null || profile.name.trim().isEmpty() ? profile.host : profile.name;
            String text = name + ": проверьте и подтвердите настройки сервера, чтобы продолжить подключение.";
            Notification notification = new Notification.Builder(this, ACTION_REQUIRED_CHANNEL)
                    .setSmallIcon(android.R.drawable.stat_sys_warning)
                    .setContentTitle("Требуется настройка SSH-хоста")
                    .setContentText(text)
                    .setStyle(new Notification.BigTextStyle().bigText(text))
                    .setCategory(Notification.CATEGORY_REMINDER)
                    .setVisibility(Notification.VISIBILITY_PRIVATE)
                    .setContentIntent(content)
                    .setAutoCancel(true)
                    .addAction(new Notification.Action.Builder(null, "Настроить", content).build())
                    .build();
            manager.notify(id, ACTION_REQUIRED_ID, notification);
            notifiedServerRequests.put(id, request);
        }
        for (String id : new HashSet<>(notifiedServerRequests.keySet())) {
            if (!waiting.contains(id)) {
                manager.cancel(id, ACTION_REQUIRED_ID);
                notifiedServerRequests.remove(id);
            }
        }
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
        // No profile ID means disconnect all connections from the summary notification.
        PendingIntent stopIntent = PendingIntent.getService(this, 1, stop,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder builder = new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setContentTitle(getString(R.string.app_name) + " · " + title).setContentText(text)
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
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, getString(R.string.app_name), NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Shows the state of the SSH SOCKS5 tunnel");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
                NotificationChannel actionChannel = new NotificationChannel(ACTION_REQUIRED_CHANNEL,
                        "Настройка SSH-хоста", NotificationManager.IMPORTANCE_DEFAULT);
                actionChannel.setDescription("Подтверждение серверного плана, когда приложение свёрнуто");
                manager.createNotificationChannel(actionChannel);
            }
        }
    }


    @Override public void onDestroy() {
        destroyed = true;
        if (runningService.get() == this) runningService.clear();
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) for (String id : notifiedServerRequests.keySet())
            manager.cancel(id, ACTION_REQUIRED_ID);
        notifiedServerRequests.clear();
        for (SshConnection c : connections.values()) c.shutdown();
        connections.clear();
        cleanup.shutdown();
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) { return super.onBind(intent); }

    @Override public void onRevoke() {
        for (SshConnection c : connections.values()) if (c.usesVpn()) c.shutdown();
        refreshNotification();
        super.onRevoke();
    }
}
