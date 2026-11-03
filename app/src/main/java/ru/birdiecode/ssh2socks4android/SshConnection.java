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

/** Owns one profile's sessions, credentials and packet channels. */
final class SshConnection {
    interface Host {
        void changed(SshConnection connection);
        void claimVpn(SshConnection connection);
        void releaseVpn(SshConnection connection);
        boolean isCurrent(SshConnection connection);
    }
    private final android.content.Context context;
    private final VpnService service;
    private final Host host;
    final String connectionId = java.util.UUID.randomUUID().toString();
    volatile String state = "CONNECTING";
    private volatile boolean cancelled;

    SshConnection(VpnService service, Host host, String profileId) {
        this.context = service;
        this.service = service;
        this.host = host;
        this.activeProfileId = profileId;
        worker.scheduleWithFixedDelay(this::checkHealth, 2, 2, java.util.concurrent.TimeUnit.SECONDS);
    }
    String profileId() { return activeProfileId; }
    boolean isLive() {
        return !cancelled && !"ERROR".equals(state) && !"IDLE".equals(state);
    }
    void execute(Runnable action) { worker.execute(() -> { if (!cancelled) action.run(); }); }
    void shutdown() { disconnect(); worker.shutdownNow(); }
    void password(String nodeId, String password) {
        if (!"NEEDS_PASSWORD".equals(state)) return;
        if (nodeId == null || password == null || password.isEmpty()) {
            fail(activeProfileId, "Пароль не задан"); return;
        }
        String request = ProfileStore.statusDetail(context, activeProfileId);
        if (!("NODE:" + nodeId).equals(request)) return;
        pendingPasswords.put(nodeId, password);
        connect(activeProfileId);
    }
    private void checkHealth() {
        if (!"CONNECTED".equals(state) || cancelled) return;
        boolean lost = activeSession == null || !activeSession.isConnected();
        if (activeTun != null && activeTun.isClosed()) lost = true;
        if (serverConfigChannel != null && serverConfigChannel.isClosed()) lost = true;
        if (lost) retryOrFail("SSH-транспорт или TUN-канал закрыт");
    }

    private void retryOrFail(String reason) {
        closeActiveSession();
        Profile profile = ProfileStore.get(context, activeProfileId);
        if (cancelled || !host.isCurrent(this)) return;
        if (profile == null || !profile.vpnAutoReconnect) { fail(activeProfileId, reason); return; }
        if (retry != null && !retry.isDone()) return;
        long ceiling = Math.min(60000L, 1000L << Math.min(retryAttempt++, 6));
        long delay = ceiling / 2 + new Random().nextInt((int) (ceiling / 2 + 1));
        setStatus(activeProfileId, "RECONNECTING", "Повторное подключение через " + delay + " мс");
        retry = worker.schedule(() -> {
            retry = null;
            if (!cancelled) connect(activeProfileId);
        }, delay, java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    private void checkCancelled() throws IOException {
        if (cancelled || !host.isCurrent(this)) throw new IOException("Подключение отменено");
    }
    private synchronized void setStatus(String profileId, String state, String detail) {
        if (!host.isCurrent(this) || (cancelled && !"IDLE".equals(state))) return;
        this.state = state;
        if (events.size() == 64) events.removeFirst();
        // Deliberately record states only: exceptions may contain server-controlled text.
        events.addLast(System.currentTimeMillis() + " " + connectionId + " " + state);
        ProfileStore.setStatus(context, profileId, state, detail);
        host.changed(this);
    }
    private void updateNotification(String title, String detail) { host.changed(this); }
    private final java.util.concurrent.ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private int retryAttempt;
    private java.util.concurrent.ScheduledFuture<?> retry;
    private final java.util.ArrayDeque<String> events = new java.util.ArrayDeque<>();
    private final List<Session> activeSessions = Collections.synchronizedList(new ArrayList<>());
    private volatile Session activeSession;
    private volatile Socks5Proxy activeProxy;
    private final String activeProfileId;
    private final Map<String, String> pendingPasswords = new java.util.concurrent.ConcurrentHashMap<>();
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


    void trustAndConnect(String targetId) {
        String pending = ProfileStore.statusDetail(context, activeProfileId);
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
        Profile node = ProfileStore.get(context, nodeId);
        if (node == null || !targetId.equals(activeProfileId)) {
            fail(targetId, "The host awaiting confirmation no longer exists");
            return;
        }
        node.hostFingerprint = fingerprint;
        node.observedFingerprint = "";
        ProfileStore.save(context, node);
        
        connect(targetId);
    }

    void connect(String targetId) {
        if (cancelled) return;
        closeActiveSession();
        Profile target = ProfileStore.get(context, targetId);
        if (target == null) { fail(targetId, "Connection profile was not found"); return; }

        List<Profile> chain;
        try {
            chain = resolveChain(target);
        } catch (Exception e) {
            fail(targetId, e.getMessage());
            return;
        }


        setStatus( targetId, "CONNECTING",
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
                session.setSocketFactory(protectedSocketFactory());
                session.setConfig("StrictHostKeyChecking", "yes");
                session.setServerAliveInterval(10000);
                session.setServerAliveCountMax(3);
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
                activeSessions.add(session);
                checkCancelled();
                setStatus(targetId, "AUTHENTICATING", "SSH: " + display(node));
                try {
                    session.connect(20_000);
                } catch (Exception e) {
                    try { session.disconnect(); } catch (Exception ignored) {}
                    String offered = pinning.getOfferedFingerprint();
                    if (!offered.isEmpty() && offered.equals(node.hostFingerprint)
                            && node.observedFingerprint != null && !node.observedFingerprint.isEmpty()) {
                        node.observedFingerprint = "";
                        ProfileStore.save(context, node);
                    }
                    if (!offered.isEmpty() && (node.hostFingerprint == null || node.hostFingerprint.isEmpty())) {
                        requestTrust(targetId, node.id, offered);
                        return;
                    }
                    if (!offered.isEmpty()) {
                        node.observedFingerprint = offered;
                        ProfileStore.save(context, node);
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
                checkCancelled();
                if (node.observedFingerprint != null && !node.observedFingerprint.isEmpty()) {
                    node.observedFingerprint = "";
                    ProfileStore.save(context, node);
                }
                if (promptedPassword != null) {
                    if (!hasSavedPassword) {
                        node.encryptedPassword = KeyVault.encrypt(promptedPassword.getBytes(StandardCharsets.UTF_8));
                        ProfileStore.save(context, node);
                    }
                    pendingPasswords.remove(node.id);
                }
                previous = session;
            }

            checkCancelled();
            activeSession = previous;
            StringBuilder connectedDetails = new StringBuilder();
            if (vpnMode) {
                setStatus(targetId, "PREPARING_TUN", "Открытие SSH TUN");
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
            checkCancelled();
            retryAttempt = 0;
            setStatus( targetId, "CONNECTED", connectedDetails.toString());
            updateNotification("SSH tunnel connected", connectedDetails + " via " + chainLabel(chain));
        } catch (Exception e) {
            String message = e instanceof NodeException
                    ? ((NodeException) e).getMessage()
                    : readableMessage(e);
            closeActiveSession();
            if (!cancelled) fail(targetId, message);
        }
    }

    private void establishVpnInterface(Profile profile) throws Exception {
        host.claimVpn(this);
        if (VpnService.prepare(context) != null) throw new IllegalStateException("Нужно разрешение Android на VPN");
        VpnService.Builder builder = service.new Builder()
                .setSession(profile.name == null || profile.name.isEmpty() ? profile.host : profile.name)
                .setMtu(profile.vpnMtu)
                .addDisallowedApplication(service.getPackageName());

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
                if (!service.protect(socket)) {
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
        setStatus(activeProfileId, "CONFIGURING_SERVER", "Настройка сервера");
        startServerTunConfig(endpoint, profile, mtu, activeTunUnit);
    }

    private void startServerTunConfig(Session endpoint, Profile profile, int mtu, int unit) throws Exception {
        String interfaceName = "tun" + unit;
        String table = "ssh2socks_" + shortProfileToken(java.util.UUID.randomUUID().toString());
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
        // Closing the descriptor first unblocks the channel's TUN read before disconnect joins it.
        ParcelFileDescriptor descriptor = vpnInterface;
        vpnInterface = null;
        if (descriptor != null) {
            try { descriptor.close(); } catch (Exception ignored) {}
        }
        OpenSshTunChannel tun = activeTun;
        activeTun = null;
        if (tun != null) {
            try { tun.disconnect(); } catch (Exception ignored) {}
        }
        activeTunUnit = -1;
        activeVpnTable = "";
        host.releaseVpn(this);
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
            node = ProfileStore.get(context, jumpId);
            if (node == null) throw new IllegalArgumentException("ProxyJump host for " + display(reversed.get(reversed.size() - 1)) + " was deleted");
            if (reversed.size() > ProfileStore.all(context).size()) throw new IllegalArgumentException("ProxyJump chain is invalid");
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
        closeActiveSession();
        setStatus( targetId, "NEEDS_PASSWORD", "NODE:" + node.id);
        updateNotification("SSH password required", "Enter password for " + node.username + "@" + node.host);
        // Keep the foreground service alive while the activity asks for the password.
    }

    private void addAllVaultKeys(JSch jsch) {
        for (SshKey key : SshKeyStore.all(context)) {
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
        
        setStatus( targetId, "NEEDS_TRUST", "NODE:" + nodeId + ":" + fingerprint);
        updateNotification("Verify SSH server", "Open the app to review its host fingerprint");
        closeActiveSession();
        host.changed(this);
    }

    void disconnect() {
        cancelled = true;
        if (retry != null) retry.cancel(false);
        closeActiveSession();
        pendingPasswords.clear();
        
        if (!activeProfileId.isEmpty()) setStatus( activeProfileId, "IDLE", "Disconnected");
        host.changed(this);
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
        setStatus( profileId, "ERROR", message == null ? "Connection failed" : message);
        updateNotification("SSH tunnel stopped", message == null ? "Connection failed" : message);
        host.changed(this);
    }

    private String readableMessage(Exception e) {
        String message = e.getMessage();
        return message == null || message.trim().isEmpty() ? e.getClass().getSimpleName() : message;
    }

    private static final class NodeException extends Exception {
        NodeException(Profile node, String reason, Throwable cause) {
            super((node.name == null || node.name.trim().isEmpty() ? node.host : node.name)
                    + " (" + node.username + "@" + node.host + "): " + reason
                    + (cause == null || cause.getMessage() == null ? "" : " — " + cause.getMessage()), cause);
        }
    }
}
