package ru.birdiecode.ssh2socks4android;

import com.jcraft.jsch.ChannelDirectTCPIP;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SocketFactory;
import com.jcraft.jsch.Proxy;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

final class SshJumpProxy implements Proxy {
    private final Session jumpSession;
    private ChannelDirectTCPIP channel;
    private InputStream input;
    private OutputStream output;
    private SshStreamSocket socket;

    SshJumpProxy(Session jumpSession) {
        this.jumpSession = jumpSession;
    }

    @Override
    public void connect(SocketFactory socketFactory, String host, int port, int timeout) throws Exception {
        if (!jumpSession.isConnected()) throw new ConnectionFailurePolicy.Failure(
                ConnectionFailurePolicy.Kind.TEMPORARY_NETWORK, "Jump server session is not connected");
        channel = (ChannelDirectTCPIP) jumpSession.openChannel("direct-tcpip");
        channel.setHost(host);
        channel.setPort(port);
        channel.setOrgIPAddress("127.0.0.1");
        channel.setOrgPort(0);
        try {
            input = channel.getInputStream();
            output = channel.getOutputStream();
            channel.connect(timeout);
        } catch (Exception e) {
            int reason = channel.getExitStatus();
            boolean connected = jumpSession.isConnected();
            try { channel.disconnect(); } catch (Exception ignored) {}
            String target = host != null && host.contains(":")
                    && !(host.startsWith("[") && host.endsWith("]")) ? "[" + host + "]" : host;
            String message = "ProxyJump server could not open a TCP forwarding channel to "
                    + target + ":" + port
                    + ". Check target reachability from the jump server and its TCP forwarding policy.";
            ConnectionFailurePolicy.Kind kind = e instanceof com.jcraft.jsch.JSchException
                    ? ConnectionFailurePolicy.channelOpen((com.jcraft.jsch.JSchException) e, reason, connected).kind
                    : e instanceof java.io.IOException
                    ? ConnectionFailurePolicy.transportIo((java.io.IOException) e, message).kind
                    : ConnectionFailurePolicy.classify(e);
            throw new ConnectionFailurePolicy.Failure(kind, message, e);
        }
        socket = new SshStreamSocket(input, output);
        input = socket.getInputStream();
        output = socket.getOutputStream();
    }

    @Override public InputStream getInputStream() { return input; }
    @Override public OutputStream getOutputStream() { return output; }

    // Expose SO_TIMEOUT so JSch keepalive also works beyond a jump host.
    @Override public Socket getSocket() { return socket; }

    @Override
    public void close() {
        SshStreamSocket current = socket;
        socket = null;
        if (current != null) { try { current.close(); } catch (java.io.IOException ignored) { } }
        if (channel != null) {
            try { channel.disconnect(); } catch (Exception ignored) {}
            channel = null;
        }
    }
}
