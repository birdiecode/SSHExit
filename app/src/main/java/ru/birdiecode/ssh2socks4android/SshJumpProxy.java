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

    SshJumpProxy(Session jumpSession) {
        this.jumpSession = jumpSession;
    }

    @Override
    public void connect(SocketFactory socketFactory, String host, int port, int timeout) throws Exception {
        if (!jumpSession.isConnected()) throw new IllegalStateException("Jump server session is not connected");
        channel = (ChannelDirectTCPIP) jumpSession.openChannel("direct-tcpip");
        channel.setHost(host);
        channel.setPort(port);
        channel.setOrgIPAddress("127.0.0.1");
        channel.setOrgPort(0);
        channel.connect(timeout);
        input = channel.getInputStream();
        output = channel.getOutputStream();
    }

    @Override public InputStream getInputStream() { return input; }
    @Override public OutputStream getOutputStream() { return output; }

    // JSch treats this socket as optional when a Proxy supplies its own streams.
    @Override public Socket getSocket() { return null; }

    @Override
    public void close() {
        if (channel != null) {
            try { channel.disconnect(); } catch (Exception ignored) {}
            channel = null;
        }
    }
}
