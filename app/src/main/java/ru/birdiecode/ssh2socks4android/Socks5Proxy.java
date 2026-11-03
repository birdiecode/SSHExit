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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class Socks5Proxy {
    private final Session session;
    private final int port;
    private final Set<Socket> clients = ConcurrentHashMap.newKeySet();
    private volatile ServerSocket server;
    private volatile ExecutorService workers;

    Socks5Proxy(Session session, int port) {
        this.session = session;
        this.port = port;
    }

    void start() throws IOException {
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
        server = socket;
        workers = Executors.newCachedThreadPool();
        Thread acceptor = new Thread(this::acceptLoop, "socks5-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    void stop() {
        ServerSocket listener = server;
        server = null;
        if (listener != null) {
            try { listener.close(); } catch (IOException ignored) {}
        }
        for (Socket client : clients) closeQuietly(client);
        ExecutorService pool = workers;
        workers = null;
        if (pool != null) pool.shutdownNow();
    }

    private void acceptLoop() {
        while (server != null) {
            try {
                ServerSocket listener = server;
                if (listener == null) return;
                Socket client = listener.accept();
                client.setReuseAddress(true);
                client.setTcpNoDelay(true);
                clients.add(client);
                ExecutorService pool = workers;
                if (pool != null) pool.execute(() -> handle(client));
                else closeQuietly(client);
            } catch (IOException e) {
                if (server != null) continue;
                return;
            }
        }
    }

    private void handle(Socket client) {
        ChannelDirectTCPIP channel = null;
        boolean successReplySent = false;
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

            if (!session.isConnected()) {
                writeReply(output, 1);
                return;
            }
            channel = (ChannelDirectTCPIP) session.openChannel("direct-tcpip");
            channel.setHost(destination);
            channel.setPort(destinationPort);
            channel.setOrgIPAddress(client.getInetAddress().getHostAddress());
            channel.setOrgPort(client.getPort());
            // Install the receive pipe before opening: a target may send its greeting immediately.
            InputStream sshInput = channel.getInputStream();
            OutputStream sshOutput = channel.getOutputStream();
            channel.connect(20_000);

            writeReply(output, 0);
            successReplySent = true;
            ChannelDirectTCPIP connectedChannel = channel;
            InputStream clientInput = client.getInputStream();
            OutputStream clientOutput = client.getOutputStream();
            Thread toSsh = new Thread(() -> copy(client, connectedChannel, clientInput, sshOutput), "socks5-to-ssh");
            Thread toClient = new Thread(() -> copy(client, connectedChannel, sshInput, clientOutput), "ssh-to-socks5");
            toSsh.setDaemon(true);
            toClient.setDaemon(true);
            toSsh.start();
            toClient.start();
            toSsh.join();
            toClient.join();
        } catch (Exception e) {
            if (!successReplySent) {
                try { writeReply(new DataOutputStream(client.getOutputStream()), 1); }
                catch (Exception ignored) {}
            }
        } finally {
            if (channel != null) {
                try { channel.disconnect(); } catch (Exception ignored) {}
            }
            closeQuietly(client);
            clients.remove(client);
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
