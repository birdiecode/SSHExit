package ru.birdiecode.ssh2socks4android;

import java.io.*;
import java.net.*;
import java.util.Locale;

/** One failure policy for initial connect, ProxyJump, discovery and server setup. */
final class ConnectionFailurePolicy {
    enum Kind { TEMPORARY_NETWORK, CONFIGURATION, AUTHENTICATION, TRUST, CANCELLED }
    static class Failure extends IOException {
        final Kind kind;
        Failure(Kind kind, String message) { super(message); this.kind = kind; }
        Failure(Kind kind, String message, Throwable cause) { super(message, cause); this.kind = kind; }
    }

    static Kind classify(Throwable error) {
        Throwable original = error;
        // Explicit boundary decisions override nested socket exceptions.
        for (int depth = 0; error != null && depth < 32; depth++, error = error.getCause()) {
            Throwable cursor = error;
            if (cursor instanceof Failure) return ((Failure) cursor).kind;
            if (cursor.getCause() == cursor) break;
        }
        error = original;
        Kind network = null;
        for (int depth = 0; error != null && depth < 32; depth++, error = error.getCause()) {
            if (error instanceof InterruptedException) return Kind.CANCELLED;
            if (error instanceof BindException || error instanceof FileNotFoundException
                    || error instanceof ProtocolException || error instanceof IllegalArgumentException
                    || error instanceof java.security.GeneralSecurityException)
                return Kind.CONFIGURATION;
            if (error instanceof SocketTimeoutException || error instanceof SocketException
                    || error instanceof UnknownHostException || error instanceof EOFException)
                network = Kind.TEMPORARY_NETWORK;
            else if (error instanceof InterruptedIOException) return Kind.CANCELLED;
            // JSch can flatten causes; inspect its own messages, not host/profile labels.
            if (error instanceof com.jcraft.jsch.JSchException) {
                String message = error.getMessage() == null ? "" : error.getMessage().toLowerCase(Locale.ROOT);
                if (message.contains("auth fail") || message.contains("authentication failed")
                        || message.contains("auth cancel") || message.contains("no more authentication methods"))
                    return Kind.AUTHENTICATION;
                if (message.contains("hostkey") || message.contains("host key")
                        || message.contains("fingerprint")) return Kind.TRUST;
                if (message.contains("vpn_protect_failed")) return Kind.CONFIGURATION;
                if (message.contains("timeout") || message.contains("timed out")
                        || message.contains("connection reset") || message.contains("connection refused")
                        || message.contains("socket closed") || message.contains("session is down")
                        || message.contains("session is not connected") || message.contains("socket is not established")
                        || message.contains("connection is closed by foreign host")
                        || message.contains("unknownhostexception") || message.contains("network is unreachable") || message.contains("no route to host"))
                    network = Kind.TEMPORARY_NETWORK;
            }
        }
        return network == null ? Kind.CONFIGURATION : network;
    }

    static Failure transportIo(IOException error, String message) {
        Kind kind = error instanceof InterruptedIOException && !(error instanceof SocketTimeoutException)
                ? Kind.CANCELLED : error instanceof ProtocolException || error instanceof FileNotFoundException
                ? Kind.CONFIGURATION : Kind.TEMPORARY_NETWORK;
        return new Failure(kind, message, error);
    }

    static Failure channelOpen(com.jcraft.jsch.JSchException error, int reason, boolean sessionConnected) {
        Kind kind = classify(error);
        String message = error.getMessage() == null ? "" : error.getMessage().toLowerCase(Locale.ROOT);
        if (message.contains("channel is not opened")) {
            // JSch records SSH_MSG_CHANNEL_OPEN_FAILURE's reason in getExitStatus().
            // -1 means no reply before timeout; 4 is SSH_OPEN_RESOURCE_SHORTAGE.
            kind = !sessionConnected || reason < 0 || reason == 4
                    ? Kind.TEMPORARY_NETWORK : Kind.CONFIGURATION;
        }
        return new Failure(kind, error.getMessage(), error);
    }

    static boolean shouldRetry(Kind kind, boolean autoReconnect, boolean cancelled, boolean current) {
        return kind == Kind.TEMPORARY_NETWORK && autoReconnect && !cancelled && current;
    }

    static Kind serverExit(int status, boolean awaitingOwnLeaseCleanup) {
        if (status < 0) return Kind.TEMPORARY_NETWORK; // No exit status: timeout/transport loss.
        // Old SSH may still hold our stable addresses until its bounded lease expires.
        if (awaitingOwnLeaseCleanup && status >= 29 && status <= 32) return Kind.TEMPORARY_NETWORK;
        return Kind.CONFIGURATION;
    }
    private ConnectionFailurePolicy() {}
}
