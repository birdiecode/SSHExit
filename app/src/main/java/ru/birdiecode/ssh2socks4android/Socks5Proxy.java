package ru.birdiecode.ssh2socks4android;

import com.jcraft.jsch.ChannelDirectTCPIP;
import com.jcraft.jsch.Session;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;

final class Socks5Proxy {
    static final int MAX_CLIENTS_PER_PROXY = 16;
    static final int MAX_CLIENTS_GLOBAL = 32;
    private static final Semaphore globalSlots = new Semaphore(MAX_CLIENTS_GLOBAL);
    // Separate bounded pools prevent handlers waiting for relay threads in their own pool.
    private static final ThreadPoolExecutor handlers = pool("socks5-client");
    private static final ThreadPoolExecutor replies = pool("socks5-reply");
    private final Semaphore clientSlots = new Semaphore(MAX_CLIENTS_PER_PROXY);
    private final Set<ChannelDirectTCPIP> channels = ConcurrentHashMap.newKeySet();

    private static ThreadPoolExecutor pool(String name) {
        AtomicInteger sequence = new AtomicInteger();
        return new ThreadPoolExecutor(0, MAX_CLIENTS_GLOBAL, 30, TimeUnit.SECONDS,
                new SynchronousQueue<>(), action -> {
                    Thread thread = new Thread(action, name + "-" + sequence.incrementAndGet());
                    thread.setDaemon(true); return thread;
                }, new ThreadPoolExecutor.AbortPolicy());
    }
    int activeClientCount() { return clients.size(); }
    static int globalClientCount() { return MAX_CLIENTS_GLOBAL - globalSlots.availablePermits(); }
    static int workerThreadCount() { return handlers.getPoolSize() + replies.getPoolSize(); }

    private final Session session;
    private final int port;
    private final String connectionId;
    private final Set<Socket> clients = ConcurrentHashMap.newKeySet();
    private volatile ServerSocket server;
    private volatile Thread acceptThread;

    Socks5Proxy(Session session, int port) { this(session, port, "socks"); }

    Socks5Proxy(Session session, int port, String connectionId) {
        this.session = session;
        this.port = port;
        this.connectionId = connectionId;
    }

    synchronized void start() throws IOException {
        if (server != null) throw new IllegalStateException("SOCKS5 already started");
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        try { socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port)); }
        catch (IOException error) { socket.close(); throw error; }
        server = socket;
        Thread acceptor = new Thread(() -> acceptLoop(socket), "socks5-accept");
        acceptThread = acceptor;
        acceptor.setDaemon(true);
        acceptor.start();
    }

    boolean isRunning() {
        ServerSocket listener = server;
        Thread acceptor = acceptThread;
        return listener != null && listener.isBound() && !listener.isClosed()
                && acceptor != null && acceptor.isAlive();
    }

    synchronized void stop() {
        ServerSocket listener = server;
        server = null;
        if (listener != null) {
            try { listener.close(); } catch (IOException ignored) {}
        }
        Thread acceptor = acceptThread;
        acceptThread = null;
        if (acceptor != null && acceptor != Thread.currentThread()) {
            try { acceptor.join(2000); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
        }
        for (Socket client : clients) closeQuietly(client);
        for (ChannelDirectTCPIP channel : channels) {
            try { channel.disconnect(); } catch (Exception ignored) { }
        }
    }

    private void acceptLoop(ServerSocket listener) {
        while (!listener.isClosed()) {
            Socket client = null;
            try {
                client = listener.accept();
                client.setTcpNoDelay(true);
                if (!clientSlots.tryAcquire()) { closeQuietly(client); continue; }
                if (!globalSlots.tryAcquire()) {
                    clientSlots.release(); closeQuietly(client); continue;
                }
                clients.add(client);
                if (server != listener || listener.isClosed()) { releaseClient(client); return; }
                Socket accepted = client;
                try {
                    handlers.execute(() -> handle(accepted, listener));
                } catch (RejectedExecutionException rejected) {
                    releaseClient(accepted);
                }
            } catch (IOException error) {
                if (client != null) closeQuietly(client);
                if (listener.isClosed()) return;
            }
        }
    }

    private void releaseClient(Socket client) {
        closeQuietly(client);
        if (clients.remove(client)) {
            clientSlots.release();
            globalSlots.release();
        }
    }

    private void handle(Socket client, ServerSocket owner) {
        ChannelDirectTCPIP channel = null;
        Future<?> reply = null;
        boolean successReplySent = false;
        AppLog.INSTANCE.record(AppLog.TRACE, connectionId, "Принят локальный SOCKS5-клиент");
        try {
            DataInputStream input = new DataInputStream(client.getInputStream());
            DataOutputStream output = new DataOutputStream(client.getOutputStream());
            client.setSoTimeout(20_000);

            int version = input.readUnsignedByte();
            int methodCount = input.readUnsignedByte();
            byte[] methods = new byte[methodCount];
            input.readFully(methods);
            boolean noAuthSupported = false;
            for (byte method : methods) if ((method & 0xff) == 0) noAuthSupported = true;
            if (version != 5 || !noAuthSupported) {
                output.write(new byte[]{5, (byte) 0xff});
                output.flush();
                return;
            }
            output.write(new byte[]{5, 0});
            output.flush();

            int requestVersion = input.readUnsignedByte();
            int command = input.readUnsignedByte();
            input.readUnsignedByte(); // reserved
            int addressType = input.readUnsignedByte();
            if (requestVersion != 5) return;
            if (command != 1) {
                writeReply(output, 7);
                return;
            }

            String destination;
            if (addressType == 1) {
                byte[] raw = new byte[4];
                input.readFully(raw);
                destination = InetAddress.getByAddress(raw).getHostAddress();
            } else if (addressType == 4) {
                byte[] raw = new byte[16];
                input.readFully(raw);
                destination = InetAddress.getByAddress(raw).getHostAddress();
            } else if (addressType == 3) {
                int length = input.readUnsignedByte();
                byte[] raw = new byte[length];
                input.readFully(raw);
                destination = new String(raw, StandardCharsets.UTF_8);
            } else {
                writeReply(output, 8);
                return;
            }
            int destinationPort = input.readUnsignedShort();
            client.setSoTimeout(0);

            if (server != owner || owner.isClosed() || !session.isConnected()) {
                writeReply(output, 1);
                return;
            }
            channel = (ChannelDirectTCPIP) session.openChannel("direct-tcpip");
            channels.add(channel);
            if (server != owner || owner.isClosed()) return;
            channel.setHost(destination);
            channel.setPort(destinationPort);
            channel.setOrgIPAddress(client.getInetAddress().getHostAddress());
            channel.setOrgPort(client.getPort());
            // Install the receive pipe before opening: a target may send its greeting immediately.
            InputStream sshInput = channel.getInputStream();
            OutputStream sshOutput = channel.getOutputStream();
            channel.connect(20_000);
            AppLog.INSTANCE.record(AppLog.DEBUG, connectionId, "SOCKS5: открыт канал direct-tcpip");

            writeReply(output, 0);
            successReplySent = true;
            ChannelDirectTCPIP connectedChannel = channel;
            InputStream clientInput = client.getInputStream();
            OutputStream clientOutput = client.getOutputStream();
            reply = replies.submit(() -> copy(client, connectedChannel, sshInput, clientOutput));
            // The bounded handler also carries client -> SSH; no extra per-client thread.
            copy(client, connectedChannel, clientInput, sshOutput);
        } catch (Exception e) {
            AppLog.INSTANCE.record(AppLog.WARN, connectionId, "SOCKS5: " + AppLog.errorCategory(e.getMessage()));
            if (!successReplySent) {
                try { writeReply(new DataOutputStream(client.getOutputStream()), 1); }
                catch (Exception ignored) {}
            }
        } finally {
            if (channel != null) {
                try { channel.disconnect(); } catch (Exception ignored) {}
            }
            if (channel != null) channels.remove(channel);
            if (reply != null) reply.cancel(true);
            releaseClient(client);
        }
    }

    private void copy(Socket client, ChannelDirectTCPIP channel, InputStream input, OutputStream output) {
        try {
            byte[] buffer = new byte[16 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
                output.flush();
            }
        } catch (IOException ignored) {
        } finally {
            closeQuietly(client);
            try { channel.disconnect(); } catch (Exception ignored) {}
        }
    }

    private static void writeReply(DataOutputStream output, int reply) throws IOException {
        output.write(new byte[]{5, (byte) reply, 0, 1, 0, 0, 0, 0, 0, 0});
        output.flush();
    }

    private static void closeQuietly(Socket socket) {
        try { socket.close(); } catch (IOException ignored) {}
    }
}
