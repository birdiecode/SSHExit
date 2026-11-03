package ru.birdiecode.ssh2socks4android;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.InterruptedIOException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

/**
 * Socket facade for SSH channel streams. JSch applies its handshake/keepalive
 * SO_TIMEOUT to this facade just as it does to a native TCP socket.
 * A bounded reader avoids polling and preserves bytes across read timeouts.
 */
final class SshStreamSocket extends Socket {
    private final TimedInput input;
    private final OutputStream output;
    private volatile boolean closed;

    SshStreamSocket(InputStream input, OutputStream output) {
        this.input = new TimedInput(input);
        this.output = output;
    }

    @Override public InputStream getInputStream() { return input; }
    @Override public OutputStream getOutputStream() { return output; }
    @Override public void setSoTimeout(int timeout) throws SocketException {
        if (timeout < 0) throw new IllegalArgumentException("Negative timeout");
        if (closed) throw new SocketException("Socket closed");
        input.timeout = timeout;
    }
    @Override public int getSoTimeout() { return input.timeout; }
    @Override public boolean isClosed() { return closed; }
    @Override public boolean isConnected() { return !closed; }
    @Override public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        try { input.close(); } finally { output.close(); }
    }

    private static final class TimedInput extends InputStream {
        private final InputStream source;
        private final byte[] ring = new byte[64 * 1024];
        private final Thread reader;
        private int head, size;
        private boolean closed, eof;
        private IOException failure;
        volatile int timeout;

        TimedInput(InputStream source) {
            this.source = source;
            reader = new Thread(this::pump, "ssh-jump-input");
            reader.setDaemon(true);
            reader.start();
        }

        private void pump() {
            byte[] buffer = new byte[16 * 1024];
            try {
                int count;
                while ((count = source.read(buffer)) >= 0) {
                    int offset = 0;
                    synchronized (this) {
                        while (offset < count) {
                            while (size == ring.length && !closed) wait();
                            if (closed) return;
                            int tail = (head + size) % ring.length;
                            int copied = Math.min(count - offset, Math.min(ring.length - size, ring.length - tail));
                            System.arraycopy(buffer, offset, ring, tail, copied);
                            offset += copied; size += copied;
                            notifyAll();
                        }
                    }
                }
                synchronized (this) { eof = true; notifyAll(); }
            } catch (IOException error) {
                synchronized (this) { if (!closed) failure = error; notifyAll(); }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                synchronized (this) {
                    if (!closed) failure = new InterruptedIOException("SSH channel reader interrupted");
                    notifyAll();
                }
            }
        }

        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
        }

        @Override public synchronized int read(byte[] bytes, int offset, int length) throws IOException {
            if (bytes == null) throw new NullPointerException();
            if (offset < 0 || length < 0 || offset > bytes.length - length) throw new IndexOutOfBoundsException();
            if (closed) throw new IOException("SSH stream closed");
            if (length == 0) return 0;
            int timeoutMs = timeout;
            long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
            while (size == 0) {
                if (closed) throw new IOException("SSH stream closed");
                if (failure != null) throw failure;
                if (eof) return -1;
                try {
                    if (timeoutMs == 0) wait();
                    else {
                        long remaining = deadline - System.nanoTime();
                        if (remaining <= 0) throw new SocketTimeoutException("SSH channel read timed out");
                        wait(remaining / 1_000_000L, (int) (remaining % 1_000_000L));
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("SSH channel read interrupted");
                }
            }
            int count = Math.min(length, Math.min(size, ring.length - head));
            System.arraycopy(ring, head, bytes, offset, count);
            head = (head + count) % ring.length;
            size -= count;
            notifyAll();
            return count;
        }

        @Override public synchronized int available() { return size; }
        @Override public void close() throws IOException {
            synchronized (this) {
                if (closed) return;
                closed = true; notifyAll();
            }
            reader.interrupt();
            source.close();
        }
    }
}
