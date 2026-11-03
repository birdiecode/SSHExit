/*
 * OpenSSH TUN channel adapter for mwiede/jsch.
 *
 * JSch does not expose a public custom-channel factory. This adapter uses the pinned
 * JSch Session's addChannel method to register a real ChannelSession subclass, then
 * emits the OpenSSH tun@openssh.com channel-open extension. Keep the JSch dependency
 * pinned and cover this adapter with OpenSSH integration tests before release.
 */
package com.jcraft.jsch;

import java.lang.reflect.Method;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.function.Consumer;

/**
 * A layer-3 OpenSSH TUN channel (SSH_TUNMODE_POINTOPOINT).
 *
 * The byte streams passed to this channel must already use OpenSSH's per-packet
 * internal uint32-length framing (the adapter removes it before SSH channel-data); see {@link ru.birdiecode.ssh2socks4android.TunPacketStreams}.
 */
public final class OpenSshTunChannel extends ChannelSession {
    public static final int MODE_POINT_TO_POINT = 1;
    public static final int TUN_ID_ANY = 0x7fffffff;

    private static final byte[] CHANNEL_TYPE = Util.str2byte("tun@openssh.com");

    private final int mode;
    private final int tunnelUnit;

    public OpenSshTunChannel(int tunnelUnit) {
        super();
        if (tunnelUnit < 0) throw new IllegalArgumentException("TUN unit must be non-negative");
        this.mode = MODE_POINT_TO_POINT;
        this.tunnelUnit = tunnelUnit;
        this.type = CHANNEL_TYPE;
        this.lwsize_max = 0x20000;
        this.lwsize = this.lwsize_max;
        this.lmpsize = 0x4000;
    }

    /**
     * Registers and opens a TUN channel on an already authenticated JSch session.
     * Call setInputStream/setOutputStream before connect() so ChannelSession can
     * start its bidirectional channel-data pump.
     */
    public void openOn(Session owner, int timeoutMillis) throws JSchException {
        if (owner == null || !owner.isConnected()) {
            throw new JSchException("SSH session is not connected");
        }
        try {
            Method addChannel = Session.class.getDeclaredMethod("addChannel", Channel.class);
            addChannel.setAccessible(true);
            Object registered = addChannel.invoke(owner, this);
            if (registered == null) throw new JSchException("SSH session is closing");
        } catch (JSchException e) {
            throw e;
        } catch (Exception e) {
            throw new JSchException("Unable to register OpenSSH TUN channel with JSch", e);
        }
        connect(timeoutMillis);
    }

    @Override
    protected Packet genChannelOpenPacket() {
        Buffer buffer = new Buffer(64 + session.getBufferMargin());
        Packet packet = new Packet(buffer);
        packet.reset();
        buffer.putByte((byte) Session.SSH_MSG_CHANNEL_OPEN);
        buffer.putString(CHANNEL_TYPE);
        buffer.putInt(id);
        buffer.putInt(lwsize);
        buffer.putInt(lmpsize);
        buffer.putInt(mode);
        buffer.putInt(tunnelUnit);
        return packet;
    }

    @Override
    public void start() throws JSchException {
        if (io == null || io.in == null) {
            throw new JSchException("OpenSSH TUN channel requires an input stream");
        }
        if (thread != null) return;
        Session owner = getSession();
        thread = new Thread(() -> OpenSshTunChannel.this.run(), "OpenSSH TUN channel " + owner.getHost());
        thread.setDaemon(true);
        thread.start();
    }
    private volatile String failureReason = "";
    private volatile long sentPackets, receivedPackets;
    private Consumer<String> eventListener = event -> {};

    public void setEventListener(Consumer<String> listener) {
        eventListener = listener == null ? event -> {} : listener;
    }
    public String getFailureReason() { return failureReason; }
    public long getSentPackets() { return sentPackets; }
    public long getReceivedPackets() { return receivedPackets; }

    private void event(String value) {
        try { eventListener.accept(value); } catch (RuntimeException ignored) { }
    }

    /**
     * The length prefix belongs to our local queue only. SSH putString supplies the
     * wire length. Sending the queue prefix as payload makes Linux treat it as AF.
     */
    @Override void run() {
        try {
            Session owner = getSession();
            DataInputStream packets = new DataInputStream(io.in);
            while (isConnected() && thread != null) {
                int first = packets.read();
                if (first < 0) { failureReason = "TUN_INPUT_EOF"; break; }
                int length = (first << 24) | (packets.readUnsignedByte() << 16)
                        | (packets.readUnsignedByte() << 8) | packets.readUnsignedByte();
                if (length <= 4 || length > 65539 || length > rmpsize)
                    throw new IOException("TUN_INVALID_DATAGRAM_SIZE");
                byte[] payload = new byte[length];
                packets.readFully(payload);
                Buffer buffer = new Buffer(length + 14 + owner.getBufferMargin());
                Packet packet = new Packet(buffer);
                packet.reset();
                buffer.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
                buffer.putInt(recipient);
                buffer.putString(payload); // Exactly one SSH string: AF + complete IP datagram.
                synchronized (this) {
                    // Do not allow Session.write to fragment a datagram on a short window.
                    while (isConnected() && thread != null && rwsize < length) wait(100);
                    if (!isConnected() || thread == null) break;
                    owner.write(packet, this, length);
                }
                sentPackets++;
                if (sentPackets == 1 || sentPackets % 64 == 0) event("TUN_SENT packets=" + sentPackets);
            }
        } catch (Exception error) {
            if (!close) {
                failureReason = "TUN_SEND_FAILED:" + error.getClass().getSimpleName();
                event(failureReason);
            }
        } finally {
            thread = null;
            if (!close) {
                if (failureReason.isEmpty()) failureReason = "TUN_SENDER_STOPPED";
                event(failureReason);
                disconnect();
            }
        }
    }

    /** JSch already removed the SSH string length; restore it only for the local decoder. */
    @Override void write(byte[] bytes, int offset, int length) throws IOException {
        try {
            if (length <= 4 || length > 65539) throw new IOException("TUN_INVALID_DATAGRAM_SIZE");
            byte[] localHeader = {(byte)(length >>> 24), (byte)(length >>> 16),
                    (byte)(length >>> 8), (byte)length};
            io.put(localHeader, 0, localHeader.length);
            io.put(bytes, offset, length);
            receivedPackets++;
            if (receivedPackets == 1 || receivedPackets % 64 == 0)
                event("TUN_RECEIVED packets=" + receivedPackets);
        } catch (IOException error) {
            failureReason = "TUN_RECEIVE_FAILED:" + error.getClass().getSimpleName();
            event(failureReason);
            throw error;
        }
    }

}
