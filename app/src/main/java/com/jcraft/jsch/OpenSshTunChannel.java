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

/**
 * A layer-3 OpenSSH TUN channel (SSH_TUNMODE_POINTOPOINT).
 *
 * The byte streams passed to this channel must already use OpenSSH's per-packet
 * uint32-length framing; see {@link ru.birdiecode.ssh2socks4android.TunPacketStreams}.
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
}
