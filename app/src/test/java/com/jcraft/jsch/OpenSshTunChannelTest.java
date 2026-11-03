package com.jcraft.jsch;

import java.io.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;
import ru.birdiecode.ssh2socks4android.TunPacketStreams;

public class OpenSshTunChannelTest {
    @Test public void sendsExactlyOneAfAndIpDatagramPerChannelMessage() throws Exception {
        byte[] ipv4 = new byte[20]; ipv4[0] = 0x45;
        byte[] ipv6 = new byte[40]; ipv6[0] = 0x60;
        ByteArrayOutputStream queue = new ByteArrayOutputStream();
        DataOutputStream framed = new DataOutputStream(queue);
        framed.writeInt(ipv4.length + 4); framed.writeInt(2); framed.write(ipv4);
        framed.writeInt(ipv6.length + 4); framed.writeInt(24); framed.write(ipv6);

        CaptureSession session = new CaptureSession();
        OpenSshTunChannel channel = new OpenSshTunChannel(1234);
        channel.setSession(session);
        channel.setInputStream(new ByteArrayInputStream(queue.toByteArray()));
        channel.setRemotePacketSize(16384);
        channel.setRemoteWindowSize(131072);
        channel.connected = true;
        channel.thread = Thread.currentThread();
        channel.run();

        assertEquals(2, session.messages.size());
        assertWireMessage(session.messages.get(0), 2, ipv4);
        assertWireMessage(session.messages.get(1), 24, ipv6);
        assertEquals(2, channel.getSentPackets());
    }

    @Test public void receivesChannelDatagramsAfterJschRemovesOuterStringLength() throws Exception {
        OpenSshTunChannel channel = new OpenSshTunChannel(1234);
        ByteArrayOutputStream tun = new ByteArrayOutputStream();
        channel.setOutputStream(TunPacketStreams.removeOpenSshFraming(tun, 1400), true);
        // Actual CHANNEL_DATA payloads contain AF + IP, with no second length field.
        byte[] ipv4 = new byte[24]; ipv4[3] = 2; ipv4[4] = 0x45;
        byte[] ipv6 = new byte[44]; ipv6[3] = 24; ipv6[4] = 0x60;
        channel.write(ipv4, 0, ipv4.length);
        channel.write(ipv6, 0, ipv6.length);
        byte[] expected = new byte[60]; expected[0] = 0x45; expected[20] = 0x60;
        assertArrayEquals(expected, tun.toByteArray());
        assertEquals(2, channel.getReceivedPackets());
    }

    private void assertWireMessage(byte[] message, int family, byte[] ip) throws Exception {
        DataInputStream wire = new DataInputStream(new ByteArrayInputStream(message));
        assertEquals(94, wire.readUnsignedByte()); // SSH_MSG_CHANNEL_DATA
        wire.readInt(); // Recipient channel
        assertEquals(ip.length + 4, wire.readInt()); // The only SSH string length
        assertEquals(family, wire.readInt()); // First word INSIDE the string is AF
        byte[] actual = new byte[ip.length]; wire.readFully(actual);
        assertArrayEquals(ip, actual);
        assertEquals(-1, wire.read());
    }

    private static final class CaptureSession extends Session {
        final List<byte[]> messages = new ArrayList<>();
        CaptureSession() throws JSchException { super(new JSch(), "test", "localhost", 22); }
        @Override public boolean isConnected() { return true; }
        @Override void write(Packet packet, Channel channel, int length) {
            messages.add(Arrays.copyOfRange(packet.buffer.buffer, 5, packet.buffer.index));
            channel.rwsize -= length;
        }
        @Override void write(Packet packet) { } // Ignore EOF/CLOSE control messages in this fixture.
    }
}
