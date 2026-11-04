package ru.birdiecode.ssh2socks4android;

import com.jcraft.jsch.SocketFactory;
import java.io.*;
import java.net.*;

/** Creates the native socket before protecting it, and protects before any TCP connect. */
final class SshTransportSocketFactory implements SocketFactory {
    interface Protector { boolean protect(Socket socket); }
    static final class ProtectionException extends IOException {
        ProtectionException() {
            super("VPN_PROTECT_FAILED: Android не смог исключить SSH-сокет из VPN. Повторно разрешите VPN в Android.");
        }
    }
    private final Protector protector;
    private final int timeout;
    SshTransportSocketFactory(Protector protector, int timeout) {
        this.protector = protector;
        this.timeout = timeout;
    }
    @Override public Socket createSocket(String host, int port) throws IOException {
        Socket socket = new Socket();
        try {
            socket.setKeepAlive(true);
            socket.setTcpNoDelay(true);
            if (protector != null) {
                // Socket construction may be lazy. Binding materializes its file descriptor.
                socket.bind(new InetSocketAddress(0));
                if (!protector.protect(socket)) throw new ProtectionException();
            }
            socket.connect(new InetSocketAddress(host, port), timeout);
            return socket;
        } catch (IOException | RuntimeException failure) {
            try { socket.close(); } catch (IOException ignored) { }
            throw failure;
        }
    }
    @Override public InputStream getInputStream(Socket socket) throws IOException { return socket.getInputStream(); }
    @Override public OutputStream getOutputStream(Socket socket) throws IOException { return socket.getOutputStream(); }

    static boolean isProtectionFailure(Throwable error) {
        for (int depth = 0; error != null && depth < 16; depth++, error = error.getCause()) {
            if (error instanceof ProtectionException) return true;
            // Some SSH wrappers flatten the original exception into their message.
            if (error.getMessage() != null && error.getMessage().contains("VPN_PROTECT_FAILED")) return true;
        }
        return false;
    }
}
