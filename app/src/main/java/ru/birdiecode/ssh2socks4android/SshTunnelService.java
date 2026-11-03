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
    private volatile ParcelFileDescriptor vpnInterface;
    private volatile OpenSshTunChannel activeTun;
    private volatile ChannelExec serverConfigChannel;
    private volatile int activeTunUnit = -1;
    private volatile String activeVpnTable = "";
    private volatile int previousIpv4Forwarding = -1;
    private volatile int previousIpv6Forwarding = -1;
    private volatile Thread vpnPacketThread;
    private static final int VPN_NOTIFICATION_ID = 42;
    private static final int DEFAULT_VPN_MTU = 1400;
    private static final String VPN_IPV4_SERVER = "10.253.0.1";
    private static final String VPN_IPV4_CLIENT = "10.253.0.2";


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

        boolean vpnMode = "VPN".equals(target.connectionMode) || "BOTH".equals(target.connectionMode);
        boolean socksMode = !"VPN".equals(target.connectionMode);
        Session previous = null;
        try {
            if (vpnMode) establishVpnInterface(target);
            for (Profile node : chain) {
                JSch jsch = new JSch();
                addAllVaultKeys(jsch);
                PinnedHostKeyRepository pinning = new PinnedHostKeyRepository(node.hostFingerprint);
                jsch.setHostKeyRepository(pinning);
                Session session = jsch.getSession(node.username, normalizeSshHost(node.host), node.sshPort);
                if (vpnMode) session.setSocketFactory(protectedSocketFactory());
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
                    if (!offered.isEmpty() && offered.equals(node.hostFingerprint)
                            && node.observedFingerprint != null && !node.observedFingerprint.isEmpty()) {
                        node.observedFingerprint = "";
                        ProfileStore.save(this, node);
                    }
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
            StringBuilder connectedDetails = new StringBuilder();
            if (vpnMode) {
                startVpnTunnel(target, previous);
                connectedDetails.append("SSH TUN VPN active");
            }
            if (socksMode) {
                Socks5Proxy proxy = new Socks5Proxy(previous, target.localPort);
                proxy.start();
                activeProxy = proxy;
                if (connectedDetails.length() > 0) connectedDetails.append(" · ");
                connectedDetails.append("SOCKS5 127.0.0.1:").append(target.localPort);
            }
            ProfileStore.setStatus(this, targetId, "CONNECTED", connectedDetails.toString());
            updateNotification("SSH tunnel connected", connectedDetails + " via " + chainLabel(chain));
        } catch (Exception e) {
            String message = e instanceof NodeException
                    ? ((NodeException) e).getMessage()
                    : readableMessage(e);
            closeActiveSession();
            fail(targetId, message);
        }
    }

    private void establishVpnInterface(Profile profile) throws Exception {
        VpnService.prepare(this);
        Builder builder = new Builder()
                .setSession(profile.name == null || profile.name.isEmpty() ? profile.host : profile.name)
                .setMtu(profile.vpnMtu)
                .addDisallowedApplication(getPackageName());

        if (profile.vpnIpv4) {
            builder.addAddress(VPN_IPV4_CLIENT, 32);
            if (profile.vpnFullTunnel) builder.addRoute("0.0.0.0", 0);
        }
        String[] ipv6 = vpnIpv6Addresses(profile);
        if (profile.vpnIpv6) {
            builder.addAddress(ipv6[1], 128);
            if (profile.vpnFullTunnel) builder.addRoute("::", 0);
        }
        if (!profile.vpnFullTunnel) {
            int count = 0;
            for (String raw : profile.vpnRoutes.split("\\r?\\n")) {
                String route = raw.trim();
                if (route.isEmpty()) continue;
                String canonical = VpnRouteTable.normalizePrefix(route);
                int slash = canonical.lastIndexOf('/');
                builder.addRoute(canonical.substring(0, slash), Integer.parseInt(canonical.substring(slash + 1)));
                count++;
            }
            if (count == 0) throw new IllegalArgumentException("Для split tunneling не заданы маршруты");
        }
        if (profile.vpnDnsServers != null && !profile.vpnDnsServers.trim().isEmpty()) {
            for (String raw : profile.vpnDnsServers.split(",")) {
                String address = raw.trim();
                if (address.isEmpty()) continue;
                if (address.indexOf(':') < 0 && !address.matches("[0-9.]+")) {
                    throw new IllegalArgumentException("DNS должен быть указан как IPv4 или IPv6 адрес");
                }
                builder.addDnsServer(java.net.InetAddress.getByName(address));
            }
        }
        ParcelFileDescriptor established = builder.establish();
        if (established == null) throw new IllegalStateException("Android не создал VPN-интерфейс");
        vpnInterface = established;
    }

    private String[] vpnIpv6Addresses(Profile profile) throws Exception {
        if (!profile.vpnIpv6Prefix.isEmpty()) {
            String canonical = VpnRouteTable.normalizePrefix(profile.vpnIpv6Prefix);
            if (!canonical.contains(":")) throw new IllegalArgumentException("Префикс VPN должен быть IPv6");
            int prefix = Integer.parseInt(canonical.substring(canonical.lastIndexOf('/') + 1));
            if (prefix > 64) throw new IllegalArgumentException("IPv6-префикс должен быть /64 или шире");
            byte[] network = java.net.InetAddress.getByName(canonical.substring(0, canonical.lastIndexOf('/'))).getAddress();
            network[15] = 1;
            String server = java.net.InetAddress.getByAddress(network).getHostAddress();
            network[15] = 2;
            String client = java.net.InetAddress.getByAddress(network).getHostAddress();
            return new String[]{server, client};
        }
        return new String[]{"fd53:5353:5353::1", "fd53:5353:5353::2"};
    }

    private SocketFactory protectedSocketFactory() {
        return new SocketFactory() {
            @Override public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
                Socket socket = new Socket();
                if (!protect(socket)) {
                    try { socket.close(); } catch (IOException ignored) {}
                    throw new IOException("Android не смог исключить SSH-сокет из VPN");
                }
                socket.connect(new InetSocketAddress(host, port), 20_000);
                return socket;
            }
            @Override public InputStream getInputStream(Socket socket) throws IOException {
                return socket.getInputStream();
            }
            @Override public OutputStream getOutputStream(Socket socket) throws IOException {
                return socket.getOutputStream();
            }
        };
    }

    private void startVpnTunnel(Profile profile, Session endpoint) throws Exception {
        ParcelFileDescriptor descriptor = vpnInterface;
        if (descriptor == null) throw new IllegalStateException("VPN-интерфейс не создан");
        activeTunUnit = 100000000 + new Random().nextInt(100000000);
        OpenSshTunChannel tun = new OpenSshTunChannel(activeTunUnit);
        int mtu = profile.vpnMtu > 0 ? profile.vpnMtu : DEFAULT_VPN_MTU;
        tun.setInputStream(TunPacketStreams.addOpenSshFraming(
                new FileInputStream(descriptor.getFileDescriptor()), mtu), true);
        tun.setOutputStream(TunPacketStreams.removeOpenSshFraming(
                new FileOutputStream(descriptor.getFileDescriptor()), mtu), true);
        tun.openOn(endpoint, 20_000);
        activeTun = tun;
        startServerTunConfig(endpoint, profile, mtu, activeTunUnit);
    }

    private void startServerTunConfig(Session endpoint, Profile profile, int mtu, int unit) throws Exception {
        String interfaceName = "tun" + unit;
        String table = "ssh2socks_" + shortProfileToken(profile.id);
        activeVpnTable = table;
        String[] ipv6 = vpnIpv6Addresses(profile);
        String script = ServerTunConfiguration.build(profile, interfaceName, table, mtu, ipv6);
        ChannelExec monitor = (ChannelExec) endpoint.openChannel("exec");
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        monitor.setErrStream(stderr);
        monitor.setCommand("sh -c " + shellQuote(script));
        InputStream stdout = monitor.getInputStream();
        monitor.connect(20_000);
        StringBuilder response = new StringBuilder();
        long deadline = System.currentTimeMillis() + 20_000;
        byte[] buffer = new byte[1024];
        boolean ready = false;
        while (System.currentTimeMillis() < deadline) {
            while (stdout.available() > 0) {
                int count = stdout.read(buffer);
                if (count < 0) break;
                response.append(new String(buffer, 0, count, StandardCharsets.UTF_8));
                if (response.indexOf("SSH2SOCKS_TUN_READY") >= 0) {
                    ready = true;
                    break;
                }
            }
            if (ready) break;
            if (monitor.isClosed()) break;
            Thread.sleep(50);
        }
        if (!ready) {
            String diagnostic = stderr.toString(StandardCharsets.UTF_8.name()).trim();
            monitor.disconnect();
            String details = response.toString().trim();
            throw new IllegalStateException("Сервер не смог настроить SSH TUN"
                    + (details.isEmpty() ? "" : ": " + details)
                    + (diagnostic.isEmpty() ? "" : " · " + diagnostic));
        }
        serverConfigChannel = monitor;
    }

    private String shortProfileToken(String profileId) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(profileId.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < 6; i++) result.append(String.format(Locale.ROOT, "%02x", digest[i]));
            return result.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to derive server resource ID", e);
        }
    }

    private String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private void closeVpnResources() {
        ChannelExec monitor = serverConfigChannel;
        serverConfigChannel = null;
        if (monitor != null) {
            try { monitor.disconnect(); } catch (Exception ignored) {}
        }
        OpenSshTunChannel tun = activeTun;
        activeTun = null;
        if (tun != null) {
            try { tun.disconnect(); } catch (Exception ignored) {}
        }
        ParcelFileDescriptor descriptor = vpnInterface;
        vpnInterface = null;
        if (descriptor != null) {
            try { descriptor.close(); } catch (Exception ignored) {}
        }
        activeTunUnit = -1;
        activeVpnTable = "";
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

    private String normalizeSshHost(String host) {
        if (host == null) return "";
        String value = host.trim();
        if (value.startsWith("[") && value.endsWith("]") && value.length() > 2) {
            return value.substring(1, value.length() - 1);
        }
        return value;
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
        closeVpnResources();
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

    @Override public IBinder onBind(Intent intent) { return super.onBind(intent); }

    @Override public void onRevoke() {
        worker.execute(this::disconnect);
        super.onRevoke();
    }

    private static final class NodeException extends Exception {
        NodeException(Profile node, String reason, Throwable cause) {
            super((node.name == null || node.name.trim().isEmpty() ? node.host : node.name)
                    + " (" + node.username + "@" + node.host + "): " + reason
                    + (cause == null || cause.getMessage() == null ? "" : " — " + cause.getMessage()), cause);
        }
    }
}
