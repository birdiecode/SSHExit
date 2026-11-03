package ru.birdiecode.ssh2socks4android;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;

import org.junit.Test;

public final class TunPacketStreamsTest {
    private static final int MTU = 1500;

    @Test
    public void outboundPacketsAreLengthPrefixedIndividually() throws Exception {
        byte[] first = new byte[] {0x45, 0, 0, 4};
        byte[] second = new byte[] {0x60, 1, 2, 3, 4, 5};
        InputStream framed = TunPacketStreams.addOpenSshFraming(
                new PacketInputStream(first, second), MTU);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[64];
        int count;
        while ((count = framed.read(buffer)) != -1) bytes.write(buffer, 0, count);

        DataInputStream decoded = new DataInputStream(new ByteArrayInputStream(bytes.toByteArray()));
        assertEquals(first.length, decoded.readInt());
        byte[] firstActual = new byte[first.length];
        decoded.readFully(firstActual);
        assertArrayEquals(first, firstActual);
        assertEquals(second.length, decoded.readInt());
        byte[] secondActual = new byte[second.length];
        decoded.readFully(secondActual);
        assertArrayEquals(second, secondActual);
        assertEquals(-1, decoded.read());
    }

    @Test
    public void inboundFramesAreWrittenAsPackets() throws Exception {
        byte[] first = new byte[] {0x45, 1, 2, 3};
        byte[] second = new byte[] {0x60, 4, 5, 6, 7};
        ByteArrayOutputStream frames = new ByteArrayOutputStream();
        writeFrame(frames, first);
        writeFrame(frames, second);
        ByteArrayOutputStream tun = new ByteArrayOutputStream();

        TunPacketStreams.copyOpenSshFramesToTun(
                new ByteArrayInputStream(frames.toByteArray()), tun, MTU);

        byte[] expected = new byte[first.length + second.length];
        System.arraycopy(first, 0, expected, 0, first.length);
        System.arraycopy(second, 0, expected, first.length, second.length);
        assertArrayEquals(expected, tun.toByteArray());
    }

    @Test
    public void rejectsFramesLargerThanConfiguredMtu() throws Exception {
        ByteArrayOutputStream frames = new ByteArrayOutputStream();
        frames.write(new byte[] {0, 0, 5, (byte) 0xdc}); // 1500
        try {
            TunPacketStreams.copyOpenSshFramesToTun(
                    new ByteArrayInputStream(frames.toByteArray()), new ByteArrayOutputStream(), 1200);
            fail("Expected an invalid-length error");
        } catch (IOException expected) {
            assertEquals("Invalid SSH TUN packet length: 1500", expected.getMessage());
        }
    }

    @Test
    public void rejectsTruncatedPacketFrame() throws Exception {
        byte[] truncated = new byte[] {0, 0, 0, 4, 0x45, 1};
        try {
            TunPacketStreams.copyOpenSshFramesToTun(
                    new ByteArrayInputStream(truncated), new ByteArrayOutputStream(), MTU);
            fail("Expected EOFException");
        } catch (java.io.EOFException expected) {
            // The frame length was valid but its payload was truncated.
        }
    }

    private static void writeFrame(ByteArrayOutputStream out, byte[] packet) throws IOException {
        int length = packet.length;
        out.write((length >>> 24) & 0xff);
        out.write((length >>> 16) & 0xff);
        out.write((length >>> 8) & 0xff);
        out.write(length & 0xff);
        out.write(packet);
    }

    private static final class PacketInputStream extends InputStream {
        private final Queue<byte[]> packets = new ArrayDeque<>();
        private byte[] current;
        private int offset;

        PacketInputStream(byte[]... packets) {
            this.packets.addAll(Arrays.asList(packets));
        }

        @Override
        public int read() {
            byte[] one = new byte[1];
            int count = read(one, 0, 1);
            return count < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] target, int targetOffset, int length) {
            if (length == 0) return 0;
            if (current == null || offset == current.length) {
                current = packets.poll();
                offset = 0;
                if (current == null) return -1;
            }
            int count = Math.min(length, current.length - offset);
            System.arraycopy(current, offset, target, targetOffset, count);
            offset += count;
            return count;
        }
    }
}
