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
        void cleanup(Runnable action);
    }
    private final android.content.Context context;
    private final VpnService service;
    private final Host host;
    final String connectionId = java.util.UUID.randomUUID().toString();
    volatile String state = "CONNECTING";
    private volatile boolean cancelled;
    private final java.util.concurrent.atomic.AtomicBoolean shutdownRequested = new java.util.concurrent.atomic.AtomicBoolean();
    private final boolean vpnRequested;
    private final ConnectionStateMachine lifecycle = new ConnectionStateMachine();

    SshConnection(VpnService service, Host host, String profileId) {
        this.context = service;
        this.service = service;
        this.host = host;
        this.activeProfileId = profileId;
        AppLog.INSTANCE.record(AppLog.INFO, connectionId, "Создано подключение");
        Profile profile = ProfileStore.get(context, profileId);
        vpnRequested = profile != null && !"SOCKS5".equals(profile.connectionMode);
        lifecycle.transition(ConnectionStateMachine.State.CONNECTING);
        worker.scheduleWithFixedDelay(this::checkHealth, 2, 2, java.util.concurrent.TimeUnit.SECONDS);
    }
    String profileId() { return activeProfileId; }
    boolean isLive() {
        return !cancelled && !"IDLE".equals(state) && (!"ERROR".equals(state) || hasRetainedVpn());
    }
    void execute(Runnable action) { worker.execute(() -> { if (!cancelled) action.run(); }); }
    boolean usesVpn() { return vpnRequested; }
    boolean hasRetainedVpn() { VpnPacketBridge bridge = vpnBridge; return bridge != null && !bridge.isClosed(); }
    private int vpnAddressSlot() { VpnPacketBridge bridge = vpnBridge; return bridge == null ? activeTunUnit : bridge.addressSlot(); }
    void shutdown() {
        if (!shutdownRequested.compareAndSet(false, true)) return;
        if ("NEEDS_SERVER_CONFIG".equals(state)) AppLog.INSTANCE.record(AppLog.INFO, connectionId, "Пользователь отменил серверный план; настройки не применялись");
        cancelled = true;
        setStatus(activeProfileId, "IDLE", "Disconnected");
        worker.shutdownNow();
        pendingPasswords.clear();
        host.cleanup(this::closeAllResources);
    }
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
        VpnPacketBridge bridge = vpnBridge;
        if (bridge != null && !bridge.failure().isEmpty()) {
            fail(activeProfileId, "Ошибка системного TUN; трафик заблокирован: " + bridge.failure());
            return;
        }
        String failure = "";
        synchronized (activeSessions) {
            for (int i = 0; i < activeSessions.size(); i++) {
                Session session = activeSessions.get(i);
                if (!session.isConnected()) {
                    failure = "SSH-узел " + (i + 1) + "/" + activeSessions.size()
                            + " (" + session.getHost() + "): соединение закрыто или истёк keepalive";
                    break;
                }
            }
        }
        if (failure.isEmpty() && (activeSession == null || !activeSession.isConnected()))
            failure = "Закрыта SSH-сессия или истёк keepalive";
        if (failure.isEmpty() && activeProxy != null && !activeProxy.isRunning())
            failure = "Локальный SOCKS5 listener остановлен";
        if (failure.isEmpty() && activeTun != null && activeTun.isClosed()) failure = "Закрыт канал SSH TUN: " + activeTun.getFailureReason();
        else if (failure.isEmpty() && serverConfigChannel != null && serverConfigChannel.isClosed())
            failure = "Завершился серверный процесс настройки TUN, exit=" + serverConfigChannel.getExitStatus();
        OutputStream control = serverConfigControl;
        if (failure.isEmpty() && control != null
                && System.nanoTime() - lastServerHeartbeatNanos >= 15_000_000_000L) {
            try {
                synchronized (control) { control.write("alive\n".getBytes(StandardCharsets.UTF_8)); control.flush(); }
                lastServerHeartbeatNanos = System.nanoTime();
                AppLog.INSTANCE.record(AppLog.TRACE, connectionId, "Отправлено подтверждение активности серверных ресурсов");
            } catch (IOException error) { failure = "Не удалось продлить серверную аренду"; }
        }
        boolean lost = !failure.isEmpty();
        if (lost && System.currentTimeMillis() - connectedAt >= 60000) retryAttempt = 0;
        if (lost) {
            AppLog.INSTANCE.record(AppLog.WARN, connectionId, failure);
            retryOrFail(failure);
        }
    }

    private void retryOrFail(String reason) {
        closeTransport();
        Profile profile = ProfileStore.get(context, activeProfileId);
        if (cancelled || !host.isCurrent(this)) return;
        if (profile == null || !profile.vpnAutoReconnect) { fail(activeProfileId, reason); return; }
        if (retry != null && !retry.isDone()) return;
        long ceiling = Math.min(60000L, 1000L << Math.min(retryAttempt++, 6));
        long delay = ceiling / 2 + new Random().nextInt((int) (ceiling / 2 + 1));
        setStatus(activeProfileId, "RECONNECTING", reason + "\nПовторное подключение через " + delay + " мс");
        AppLog.INSTANCE.record(AppLog.DEBUG, connectionId, "Повторная попытка " + retryAttempt + ", задержка " + delay + " мс");
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
        if ("IDLE".equals(state)) lifecycle.disconnect();
        else lifecycle.transition(ConnectionStateMachine.State.valueOf(state));
        this.state = state;
        if (events.size() == 64) events.removeFirst();
        // Deliberately record states only: exceptions may contain server-controlled text.
        events.addLast(System.currentTimeMillis() + " " + connectionId + " " + state);
        AppLog.INSTANCE.record("ERROR".equals(state) ? AppLog.ERROR :
                "RECONNECTING".equals(state) ? AppLog.WARN : AppLog.INFO,
                connectionId, "Состояние: " + state);
        if ("ERROR".equals(state) || "RECONNECTING".equals(state))
            AppLog.INSTANCE.record(AppLog.ERROR, connectionId, AppLog.errorCategory(detail));
        ProfileStore.setStatus(context, profileId, state, detail);
        host.changed(this);
    }
    private void updateNotification(String title, String detail) { host.changed(this); }
    private final java.util.concurrent.ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private int retryAttempt;
    private long connectedAt;
    private java.util.concurrent.ScheduledFuture<?> retry;
    private final java.util.ArrayDeque<String> events = new java.util.ArrayDeque<>();
    private final List<Session> activeSessions = Collections.synchronizedList(new ArrayList<>());
    private volatile Session activeSession;
    private volatile Socks5Proxy activeProxy;
    private final String activeProfileId;
    private final Map<String, String> pendingPasswords = new java.util.concurrent.ConcurrentHashMap<>();
    private final Object vpnLock = new Object();
    private volatile VpnPacketBridge vpnBridge;
    private boolean vpnEverConnected;
    static final String VPN_BLOCKED_PREFIX = "VPN_BLOCKED: ";
    private volatile OpenSshTunChannel activeTun;
    private volatile ChannelExec serverConfigChannel;
    private volatile OutputStream serverConfigControl;
    private volatile Thread serverOutputThread;
    private static final class ServerRun {
        final Profile profile;
        final String interfaceName, table;
        final String[] ipv6;
        final int addressSlot;
        volatile boolean cleanupConfirmed;
        ServerRun(Profile profile, String interfaceName, String table, String[] ipv6, int addressSlot) {
            this.profile = profile; this.interfaceName = interfaceName; this.table = table;
            this.ipv6 = ipv6.clone(); this.addressSlot = addressSlot;
        }
    }
    private volatile ServerRun serverRun;
    private String pendingServerRequest = "";

    private volatile int activeTunUnit = -1;
    private volatile String activeVpnTable = "";
    private volatile int previousIpv4Forwarding = -1;
    private volatile int previousIpv6Forwarding = -1;
    private volatile Thread vpnPacketThread;
    private static final int VPN_NOTIFICATION_ID = 42;
    private static final int DEFAULT_VPN_MTU = 1400;
    private long lastServerHeartbeatNanos;


    void trustAndConnect(String targetId) {
        if (!"NEEDS_TRUST".equals(state)) return;
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
        closeTransport();
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
            if (vpnMode) {
                activeTunUnit = TunAddressPlan.FIRST_UNIT + new java.security.SecureRandom().nextInt(TunAddressPlan.UNIT_COUNT);
                establishVpnInterface(target);
            }
            for (Profile node : chain) {
                AppLog.INSTANCE.record(AppLog.DEBUG, connectionId, "SSH-узел " + (chain.indexOf(node) + 1) + "/" + chain.size());
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
                    if (!offered.isEmpty() && !offered.equals(node.hostFingerprint)) {
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
                AppLog.INSTANCE.record(AppLog.DEBUG, connectionId, "SSH-узел аутентифицирован");
                AppLog.INSTANCE.record(AppLog.DEBUG, connectionId,
                        "SSH keepalive: узел " + (chain.indexOf(node) + 1) + "/" + chain.size()
                                + ", интервал 10 с, до 3 запросов без ответа");
                previous = session;
            }

            checkCancelled();
            activeSession = previous;
            if (vpnMode) {
                requestServerPlan(target, previous);
                return;
            }
            completeConnection(target);
        } catch (Exception e) {
            AppLog.INSTANCE.record(AppLog.DEBUG, connectionId, "Тип исключения: " + e.getClass().getSimpleName());
            String message = e instanceof NodeException
                    ? ((NodeException) e).getMessage()
                    : readableMessage(e);
            handleConnectFailure(e, message);
        }
    }


    private void completeConnection(Profile target) throws Exception {
        String targetId = activeProfileId;
        List<Profile> chain = resolveChain(target);
        boolean vpnMode = !"SOCKS5".equals(target.connectionMode);
        boolean socksMode = !"VPN".equals(target.connectionMode);
        Session previous = activeSession;
            StringBuilder connectedDetails = new StringBuilder();
            if (vpnMode) {
                setStatus(targetId, "PREPARING_TUN", "Открытие SSH TUN");
                startVpnTunnel(target, previous);
                connectedDetails.append("SSH TUN VPN active");
            }
            if (socksMode) {
                Socks5Proxy proxy = new Socks5Proxy(previous, target.localPort, connectionId);
                proxy.start();
                activeProxy = proxy;
                AppLog.INSTANCE.record(AppLog.INFO, connectionId, "SOCKS5 слушает 127.0.0.1:" + target.localPort);
                if (connectedDetails.length() > 0) connectedDetails.append(" · ");
                connectedDetails.append("SOCKS5 127.0.0.1:").append(target.localPort);
            }
            checkCancelled();
            if (vpnMode) vpnEverConnected = true;
            connectedAt = System.currentTimeMillis();
            setStatus( targetId, "CONNECTED", connectedDetails.toString());
            updateNotification("SSH tunnel connected", connectedDetails + " via " + chainLabel(chain));
    }

    private void requestServerPlan(Profile target, Session endpoint) throws Exception {
        activeVpnTable = "ssh2socks_" + shortProfileToken(java.util.UUID.randomUUID().toString());
        String wan = target.vpnExternalInterface.trim();
        if (target.vpnIpv4 && wan.isEmpty()) {
            ChannelExec probe = (ChannelExec) endpoint.openChannel("exec");
            try {
                probe.setCommand("ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}'");
                InputStream output = probe.getInputStream();
                probe.connect(10000);
                ByteArrayOutputStream value = new ByteArrayOutputStream();
                long deadline = System.currentTimeMillis() + 10000;
                while (System.currentTimeMillis() < deadline) {
                    checkCancelled();
                    while (output.available() > 0 && value.size() < 256) value.write(output.read());
                    if (probe.isClosed()) break;
                    Thread.sleep(25);
                }
                wan = value.toString("UTF-8").trim();
                if (!wan.matches("[A-Za-z0-9_.:-]{1,15}"))
                    throw new IOException("Не удалось определить внешний IPv4-интерфейс сервера");
            } finally { probe.disconnect(); }
        }
        if (target.serverSkipConfirmation) {
            checkCancelled();
            target.vpnExternalInterface = wan;
            AppLog.INSTANCE.record(AppLog.INFO, connectionId,
                    "Используются сохранённые настройки сервера без запроса (выбор пользователя)");
            logServerPlan(target);
            completeConnection(target);
            return;
        }
        String[] ipv6 = vpnIpv6Addresses(target);
        pendingServerRequest = java.util.UUID.randomUUID().toString();
        org.json.JSONObject request = new org.json.JSONObject();
        request.put("requestId", pendingServerRequest);
        request.put("interface", "tun" + activeTunUnit);
        request.put("table", activeVpnTable);
        request.put("addressSlot", vpnAddressSlot());
        request.put("wan", wan);
        String[] ipv4 = TunAddressPlan.ipv4(vpnAddressSlot());
        request.put("ipv4Server", ipv4[0]); request.put("ipv4Client", ipv4[1]);
        request.put("ipv6Server", ipv6[0]); request.put("ipv6Client", ipv6[1]);
        setStatus(activeProfileId, "NEEDS_SERVER_CONFIG", request.toString());
        AppLog.INSTANCE.record(AppLog.INFO, connectionId, "Ожидание подтверждения серверного плана; команды настройки ещё не выполнялись");
    }

    void applyServerPlan(Intent intent) {
        if (!"NEEDS_SERVER_CONFIG".equals(state) || pendingServerRequest.isEmpty()
                || !pendingServerRequest.equals(intent.getStringExtra("server_request"))) return;
        try {
            checkCancelled();
            if (activeSession == null || !activeSession.isConnected())
                throw new IOException("SSH-сессия закрыта; подключитесь заново");
            Profile profile = ProfileStore.get(context, activeProfileId);
            if (profile == null) throw new IOException("Профиль удалён");
            profile.vpnExternalInterface = intent.getStringExtra("server_wan");
            if (profile.vpnExternalInterface == null) profile.vpnExternalInterface = "";
            if (profile.vpnIpv4 && profile.vpnExternalInterface.isEmpty())
                throw new IllegalArgumentException("Укажите внешний интерфейс IPv4");
            profile.serverSkipConfirmation = intent.getBooleanExtra("serverSkipConfirmation", false);
            profile.serverManageIpv4Forwarding = intent.getBooleanExtra("serverManageIpv4Forwarding", true);
            profile.serverManageIpv6Forwarding = intent.getBooleanExtra("serverManageIpv6Forwarding", true);
            profile.serverNatIpv4 = intent.getBooleanExtra("serverNatIpv4", true);
            profile.serverAcceptOutbound = intent.getBooleanExtra("serverAcceptOutbound", true);
            profile.serverAcceptReturn = intent.getBooleanExtra("serverAcceptReturn", true);
            ServerTunConfiguration.preview(profile, "tun" + activeTunUnit, activeVpnTable, vpnIpv6Addresses(profile), vpnAddressSlot());
            ProfileStore.save(context, profile);
            pendingServerRequest = "";
            AppLog.INSTANCE.record(AppLog.INFO, connectionId, "Серверные параметры подтверждены и сохранены в профиле");
            AppLog.INSTANCE.record(AppLog.INFO, connectionId, profile.serverSkipConfirmation
                    ? "Повторный запрос настроек сервера отключён для этого хоста"
                    : "Настройки сервера будут запрашиваться при следующем подключении");
            logServerPlan(profile);
            completeConnection(profile);
        } catch (Exception error) {
            AppLog.INSTANCE.record(AppLog.ERROR, connectionId, "Не удалось применить серверный план: " + error.getClass().getSimpleName());
            handleConnectFailure(error, readableMessage(error));
        }
    }

    private void logServerPlan(Profile profile) throws Exception {
        String plan = ServerTunConfiguration.preview(profile, "tun" + activeTunUnit, activeVpnTable, vpnIpv6Addresses(profile), vpnAddressSlot());
        for (String line : plan.split("\n")) AppLog.INSTANCE.record(AppLog.INFO, connectionId, "ПЛАН: " + line);
    }

    private void recordServerLine(ServerRun run, String line) {
        if (line.startsWith("SSHEXIT_APPLIED:")) {
            String description = ServerTunConfiguration.appliedDescription(line.substring("SSHEXIT_APPLIED:".length()),
                    run.profile, run.interfaceName, run.table, run.ipv6, run.addressSlot);
            if (!description.isEmpty())
                for (String item : description.split("\n"))
                    AppLog.INSTANCE.record(AppLog.INFO, connectionId, "ПРИМЕНЕНО: " + item);
        } else if ("SSHEXIT_CLEANUP_DONE".equals(line)) {
            run.cleanupConfirmed = true;
            AppLog.INSTANCE.record(AppLog.INFO, connectionId, "Сервер подтвердил удаление правил, маршрутов и адресов этого клиента; forwarding сохранён для других клиентов");
        } else if ("SSHEXIT_LEASE_EXPIRED".equals(line)) {
            AppLog.INSTANCE.record(AppLog.WARN, connectionId, "Серверная аренда истекла: начата очистка ресурсов этого клиента");
        } else if (line.startsWith("SSHEXIT_CLEANUP_STEP_FAILED:")) {
            String resource = line.substring("SSHEXIT_CLEANUP_STEP_FAILED:".length());
            if (resource.matches("(route|address)[46]"))
                AppLog.INSTANCE.record(AppLog.ERROR, connectionId, "Ошибка удаления ресурса клиента: " + resource);
        } else if ("SSHEXIT_CLEANUP_FAILED".equals(line)) {
            AppLog.INSTANCE.record(AppLog.ERROR, connectionId, "Сервер сообщил об ошибке очистки ресурсов");
        }
    }

    private void establishVpnInterface(Profile profile) throws Exception {
        checkCancelled();
        VpnPacketBridge retained = vpnBridge;
        if (retained != null) {
            if (!retained.failure().isEmpty()) throw new IllegalStateException("Системный TUN недоступен");
            AppLog.INSTANCE.record(AppLog.DEBUG, connectionId, "Сохранён системный TUN; трафик блокируется до восстановления SSH");
            return;
        }
        host.claimVpn(this);
        if (VpnService.prepare(context) != null) throw new IllegalStateException("Нужно разрешение Android на VPN");
        VpnService.Builder builder = service.new Builder()
                .setSession(profile.name == null || profile.name.isEmpty() ? profile.host : profile.name)
                .setMtu(profile.vpnMtu)
                .setBlocking(false)
                .addDisallowedApplication(service.getPackageName());

        if (profile.vpnIpv4) {
            builder.addAddress(TunAddressPlan.ipv4(activeTunUnit)[1], 32);
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
        VpnPacketBridge created = new VpnPacketBridge(new AndroidTunDevice(established), profile.vpnMtu, activeTunUnit);
        try {
            synchronized (vpnLock) {
                checkCancelled();
                vpnBridge = created;
            }
        } catch (Exception error) { created.close(); throw error; }
        AppLog.INSTANCE.record(AppLog.DEBUG, connectionId, "Android TUN создан; передача заблокирована до готовности SSH, MTU=" + profile.vpnMtu);
    }

    private String[] vpnIpv6Addresses(Profile profile) throws Exception {
        return TunAddressPlan.ipv6(vpnAddressSlot(), profile.vpnIpv6Prefix);
    }

    private SocketFactory protectedSocketFactory() {
        return new SshTransportSocketFactory(vpnRequested ? socket -> {
            AppLog.INSTANCE.record(AppLog.TRACE, connectionId,
                    "SSH-сокет создан: bound=" + socket.isBound() + ", connected=" + socket.isConnected());
            boolean protectedSocket = service.protect(socket);
            AppLog.INSTANCE.record(protectedSocket ? AppLog.DEBUG : AppLog.ERROR, connectionId,
                    "Защита SSH-сокета: " + (protectedSocket ? "успешно" : "отказ Android"));
            return protectedSocket;
        } : null, 20_000);
    }

    private void startVpnTunnel(Profile profile, Session endpoint) throws Exception {
        VpnPacketBridge bridge = vpnBridge;
        if (bridge == null) throw new IllegalStateException("VPN-интерфейс не создан");
        if (activeTunUnit < 0) throw new IllegalStateException("Серверный план не подготовлен");
        checkCancelled();
        VpnPacketBridge.Endpoint packets = bridge.prepareEndpoint();
        OpenSshTunChannel tun = new OpenSshTunChannel(activeTunUnit);
        tun.setEventListener(event -> AppLog.INSTANCE.record(event.contains("FAILED") ? AppLog.ERROR : AppLog.TRACE,
                connectionId, event));
        int mtu = profile.vpnMtu > 0 ? profile.vpnMtu : DEFAULT_VPN_MTU;
        tun.setInputStream(packets.outgoing(), true);
        tun.setOutputStream(packets.incoming(), true);
        activeTun = tun;
        try {
            tun.openOn(endpoint, 20_000);
            checkCancelled();
            AppLog.INSTANCE.record(AppLog.DEBUG, connectionId, "SSH TUN открыт, unit=" + activeTunUnit);
            setStatus(activeProfileId, "CONFIGURING_SERVER", "Настройка сервера");
            startServerTunConfig(endpoint, profile, mtu, activeTunUnit);
            checkCancelled();
            packets.enable();
            AppLog.INSTANCE.record(AppLog.INFO, connectionId, "Передача VPN разрешена после восстановления SSH и настройки сервера");
        } catch (Exception error) {
            bridge.block();
            tun.disconnect();
            throw error;
        }
    }

    private void startServerTunConfig(Session endpoint, Profile profile, int mtu, int unit) throws Exception {
        String interfaceName = "tun" + unit;
        String table = activeVpnTable;
        activeVpnTable = table;
        String[] ipv6 = vpnIpv6Addresses(profile);
        String script = ServerTunConfiguration.build(profile, interfaceName, table, mtu, ipv6, vpnAddressSlot());
        ServerRun run = new ServerRun(profile, interfaceName, table, ipv6, vpnAddressSlot());
        serverRun = run;
        ChannelExec monitor = (ChannelExec) endpoint.openChannel("exec");
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        monitor.setErrStream(stderr);
        monitor.setCommand("sh -c " + shellQuote(script));
        InputStream stdout = monitor.getInputStream();
        serverConfigControl = monitor.getOutputStream();
        serverConfigChannel = monitor;
        lastServerHeartbeatNanos = System.nanoTime();
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
        int lastNewline = response.lastIndexOf("\n");
        if (lastNewline >= 0) for (String line : response.substring(0, lastNewline).split("\n")) recordServerLine(run, line);
        if (!ready) {
            String diagnostic = stderr.toString(StandardCharsets.UTF_8.name()).trim();
            monitor.disconnect();
            String details = response.toString().trim();
            throw new ServerSetupException(monitor.getExitStatus(), "Сервер не смог настроить SSH TUN"
                    + (details.isEmpty() ? "" : ": " + details)
                    + (diagnostic.isEmpty() ? "" : " · " + diagnostic));
        }
        String remainder = lastNewline < 0 ? response.toString() : response.substring(lastNewline + 1);
        InputStream events = new java.io.SequenceInputStream(
                new java.io.ByteArrayInputStream(remainder.getBytes(StandardCharsets.UTF_8)), stdout);
        Thread reader = new Thread(() -> {
            try {
                BufferedReader lines = new BufferedReader(new InputStreamReader(events, StandardCharsets.UTF_8));
                String line;
                while ((line = lines.readLine()) != null) recordServerLine(run, line);
            } catch (IOException ignored) { }
        }, "server-events-" + connectionId.substring(0, 8));
        reader.setDaemon(true);
        serverOutputThread = reader;
        reader.start();
        AppLog.INSTANCE.record(AppLog.INFO, connectionId, "Серверная настройка TUN завершена");
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

    private void closeVpnTransportResources() {
        ChannelExec monitor = serverConfigChannel;
        ServerRun run = serverRun;
        serverRun = null;
        serverConfigChannel = null;
        if (monitor != null) {
            AppLog.INSTANCE.record(AppLog.INFO, connectionId, "Запрошена очистка серверных ресурсов");
            try {
                OutputStream control = serverConfigControl;
                serverConfigControl = null;
                if (control != null) { synchronized (control) { control.write("stop\n".getBytes(StandardCharsets.UTF_8)); control.flush(); } }
                Thread reader = serverOutputThread;
                if (reader != null && reader != Thread.currentThread()) reader.join(2000);
            } catch (Exception ignored) { }
            if (run == null || !run.cleanupConfirmed)
                AppLog.INSTANCE.record(AppLog.WARN, connectionId, "Очистка сервера не подтверждена (сеть или SSH могли быть недоступны)");
            try { monitor.disconnect(); } catch (Exception ignored) { }
            serverOutputThread = null;
        }
        OpenSshTunChannel tun = activeTun;
        activeTun = null;
        if (tun != null) {
            try { tun.disconnect(); } catch (Exception ignored) {}
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
        closeTransport();
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
        closeTransport();
        host.changed(this);
    }

    void disconnect() {
        cancelled = true;
        if (retry != null) retry.cancel(false);
        closeAllResources();
        pendingPasswords.clear();
        
        if (!activeProfileId.isEmpty()) setStatus( activeProfileId, "IDLE", "Disconnected");
        host.changed(this);
    }

    private void closeTransport() {
        VpnPacketBridge bridge = vpnBridge;
        if (bridge != null) bridge.block();
        Socks5Proxy proxy = activeProxy;
        activeProxy = null;
        if (proxy != null) proxy.stop();
        AppLog.INSTANCE.record(AppLog.TRACE, connectionId, "Освобождение SSH-ресурсов; системный TUN сохраняется");
        closeVpnTransportResources();
        activeSession = null;
        synchronized (activeSessions) {
            for (int i = activeSessions.size() - 1; i >= 0; i--) {
                try { activeSessions.get(i).disconnect(); } catch (Exception ignored) {}
            }
            activeSessions.clear();
        }
    }

    private void closeAllResources() {
        closeTransport();
        VpnPacketBridge bridge;
        synchronized (vpnLock) { bridge = vpnBridge; vpnBridge = null; }
        if (bridge != null) {
            try { bridge.close(); } catch (IOException ignored) { }
        }
        host.releaseVpn(this);
        AppLog.INSTANCE.record(AppLog.INFO, connectionId, "Системный TUN закрыт по завершении VPN");
    }

    private static final class ServerSetupException extends IOException {
        final boolean retryable;
        ServerSetupException(int exitStatus, String message) {
            super(message);
            retryable = exitStatus < 0 || exitStatus == 22 || exitStatus == 24
                    || (exitStatus >= 29 && exitStatus <= 32);
        }
    }

    private void handleConnectFailure(Exception error, String message) {
        if (cancelled || !host.isCurrent(this)) { closeTransport(); return; }
        boolean nodeRetry = error instanceof NodeException && error.getCause() != null
                && !message.toLowerCase(Locale.ROOT).contains("fingerprint") && !isAuthenticationFailure(error);
        boolean vpnRetry = hasRetainedVpn() && vpnEverConnected
                && (error instanceof IOException || error instanceof com.jcraft.jsch.JSchException)
                && (!(error instanceof ServerSetupException) || ((ServerSetupException) error).retryable);
        if (!SshTransportSocketFactory.isProtectionFailure(error) && (nodeRetry || vpnRetry)) retryOrFail(message);
        else fail(activeProfileId, message);
    }

    private void fail(String profileId, String message) {
        closeTransport();
        pendingPasswords.clear();
        if (retry != null) { retry.cancel(false); retry = null; }
        String detail = message == null ? "Connection failed" : message;
        if (hasRetainedVpn()) {
            detail = VPN_BLOCKED_PREFIX + detail;
            AppLog.INSTANCE.record(AppLog.WARN, connectionId, "VPN сохраняет блокировку трафика до повторного подключения или ручного отключения");
        }
        setStatus(profileId, "ERROR", detail);
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
