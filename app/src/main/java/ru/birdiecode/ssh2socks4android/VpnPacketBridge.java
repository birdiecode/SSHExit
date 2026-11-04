package ru.birdiecode.ssh2socks4android;

import java.io.*;
import java.util.ArrayDeque;
import java.util.Arrays;

/**
 * Owns the system TUN for its entire lifetime. Blocking/detaching an SSH endpoint
 * never closes PacketIo. While blocked, the reader drains and drops packets.
 */
final class VpnPacketBridge implements AutoCloseable {
    interface PacketIo extends AutoCloseable {
        /** One IP datagram; zero means poll timeout, negative means EOF. */
        int readPacket(byte[] packet) throws IOException;
        void writePacket(byte[] packet, int offset, int length) throws IOException;
        @Override void close() throws IOException;
    }
    private static final int QUEUE_CAPACITY = 64;
    private final PacketIo io;
    private final int mtu, addressSlot;
    private final Thread reader;
    private volatile boolean closed;
    private volatile String failure = "";
    private Endpoint current;
    private long droppedPackets;

    VpnPacketBridge(PacketIo io, int mtu, int addressSlot) {
        if (io == null || mtu < 576 || mtu > 65535) throw new IllegalArgumentException("Invalid TUN bridge");
        this.io = io; this.mtu = mtu; this.addressSlot = addressSlot;
        reader = new Thread(this::readLoop, "android-vpn-packets");
        reader.setDaemon(true); reader.start();
    }
    int addressSlot() { return addressSlot; }
    String failure() { return failure; }
    boolean isClosed() { return closed; }
    synchronized long droppedPackets() { return droppedPackets; }

    synchronized Endpoint prepareEndpoint() throws IOException {
        if (closed || !failure.isEmpty()) throw new IOException("VPN packet bridge unavailable");
        block();
        current = new Endpoint();
        return current;
    }

    synchronized void block() {
        Endpoint old = current;
        current = null;
        if (old != null) old.frames.finish();
    }

    private void readLoop() {
        byte[] packet = new byte[mtu];
        try {
            while (!closed) {
                int count = io.readPacket(packet);
                if (count < 0) throw new EOFException("TUN input closed");
                if (count == 0) continue;
                if (count > mtu) throw new IOException("Oversized TUN packet");
                int version = packet[0] >>> 4 & 15;
                synchronized (this) {
                    if (closed) return;
                    if (current == null || !current.enabled || (version != 4 && version != 6)) {
                        droppedPackets++; continue;
                    }
                    byte[] frame = new byte[count + 8];
                    int length = count + 4;
                    frame[0] = (byte)(length >>> 24); frame[1] = (byte)(length >>> 16);
                    frame[2] = (byte)(length >>> 8); frame[3] = (byte)length;
                    frame[7] = (byte)(version == 4 ? 2 : 24);
                    System.arraycopy(packet, 0, frame, 8, count);
                    if (!current.frames.offer(frame)) droppedPackets++;
                }
            }
        } catch (IOException error) {
            synchronized (this) {
                if (!closed) { failure = error.getClass().getSimpleName(); block(); }
            }
        }
    }

    final class Endpoint {
        private final FrameQueue frames = new FrameQueue();
        private boolean enabled;
        private final OutputStream incoming = TunPacketStreams.removeOpenSshFraming(new OutputStream() {
            @Override public void write(int value) throws IOException { throw new IOException("IP packet required"); }
            @Override public void write(byte[] packet, int offset, int length) throws IOException {
                synchronized (VpnPacketBridge.this) {
                    if (!closed && current == Endpoint.this && enabled)
                        io.writePacket(packet, offset, length);
                }
            }
            // SSH channel teardown must never close the shared system TUN.
            @Override public void close() {}
        }, mtu);

        InputStream outgoing() { return frames; }
        OutputStream incoming() { return incoming; }

        void enable() throws IOException {
            synchronized (VpnPacketBridge.this) {
                if (closed || current != this || !failure.isEmpty())
                    throw new IOException("Stale VPN endpoint");
                enabled = true;
            }
        }
    }

    private static final class FrameQueue extends InputStream {
        private final ArrayDeque<byte[]> packets = new ArrayDeque<>();
        private byte[] packet;
        private int offset;
        private boolean finished;

        synchronized boolean offer(byte[] frame) {
            if (finished || packets.size() >= QUEUE_CAPACITY) return false;
            packets.addLast(frame); notifyAll(); return true;
        }
        synchronized void finish() {
            finished = true; packets.clear(); packet = null; offset = 0; notifyAll();
        }
        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
        }
        @Override public synchronized int read(byte[] bytes, int start, int length) throws IOException {
            if (bytes == null) throw new NullPointerException();
            if (start < 0 || length < 0 || start > bytes.length - length) throw new IndexOutOfBoundsException();
            if (length == 0) return 0;
            while (!finished && packet == null && packets.isEmpty()) {
                try { wait(); } catch (InterruptedException error) {
                    Thread.currentThread().interrupt(); throw new InterruptedIOException("VPN endpoint interrupted");
                }
            }
            if (finished) return -1;
            if (packet == null) { packet = packets.removeFirst(); offset = 0; }
            int count = Math.min(length, packet.length - offset);
            System.arraycopy(packet, offset, bytes, start, count);
            offset += count;
            if (offset == packet.length) { packet = null; offset = 0; }
            return count;
        }
        @Override public void close() { finish(); }
    }

    @Override public void close() throws IOException {
        synchronized (this) {
            if (closed) return;
            closed = true; block();
        }
        try { io.close(); }
        finally {
            reader.interrupt();
            if (reader != Thread.currentThread()) {
                try { reader.join(1000); }
                catch (InterruptedException error) { Thread.currentThread().interrupt(); }
            }
        }
    }
}
