package ru.birdiecode.ssh2socks4android;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Encodes Android TUN packets using OpenSSH's tun@openssh.com packet framing.
 * The channel data stream is a byte stream; packet boundaries are carried by a
 * uint32 network-byte-order length before each layer-3 packet.
 */
public final class TunPacketStreams {
    private TunPacketStreams() {}

    public static InputStream addOpenSshFraming(InputStream tunInput, int mtu) {
        if (tunInput == null) throw new IllegalArgumentException("TUN input is required");
        validateMtu(mtu);
        return new FramedPacketInputStream(tunInput, mtu);
    }

    /**
     * Reads framed OpenSSH packets from the SSH channel and writes one complete
     * IP packet at a time to the Android TUN output.
     */
    public static void copyOpenSshFramesToTun(InputStream channelInput, OutputStream tunOutput, int mtu)
            throws IOException {
        if (channelInput == null || tunOutput == null) throw new IllegalArgumentException("Streams are required");
        validateMtu(mtu);
        DataInputStream data = new DataInputStream(channelInput);
        byte[] packet = new byte[mtu];
        while (true) {
            int length;
            try {
                length = data.readInt();
            } catch (EOFException end) {
                return;
            }
            if (length <= 0 || length > mtu) {
                throw new IOException("Invalid SSH TUN packet length: " + length);
            }
            data.readFully(packet, 0, length);
            tunOutput.write(packet, 0, length);
            tunOutput.flush();
        }
    }

    private static void validateMtu(int mtu) {
        if (mtu < 576 || mtu > 65535) throw new IllegalArgumentException("MTU must be between 576 and 65535");
    }

    private static final class FramedPacketInputStream extends InputStream {
        private final InputStream tunInput;
        private final int mtu;
        private final byte[] framed;
        private int offset;
        private int available;
        private boolean closed;

        FramedPacketInputStream(InputStream tunInput, int mtu) {
            this.tunInput = tunInput;
            this.mtu = mtu;
            this.framed = new byte[mtu + 4];
        }

        @Override
        public synchronized int read() throws IOException {
            byte[] one = new byte[1];
            int count = read(one, 0, 1);
            return count < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public synchronized int read(byte[] output, int outputOffset, int outputLength) throws IOException {
            if (closed) throw new IOException("Stream is closed");
            if (output == null) throw new NullPointerException("output");
            if (outputOffset < 0 || outputLength < 0 || outputLength > output.length - outputOffset) {
                throw new IndexOutOfBoundsException();
            }
            if (outputLength == 0) return 0;
            if (available == 0 && !loadPacket()) return -1;
            int count = Math.min(outputLength, available);
            System.arraycopy(framed, offset, output, outputOffset, count);
            offset += count;
            available -= count;
            return count;
        }

        private boolean loadPacket() throws IOException {
            byte[] packet = new byte[mtu];
            int length;
            do {
                length = tunInput.read(packet, 0, packet.length);
            } while (length == 0);
            if (length < 0) return false;
            framed[0] = (byte) (length >>> 24);
            framed[1] = (byte) (length >>> 16);
            framed[2] = (byte) (length >>> 8);
            framed[3] = (byte) length;
            System.arraycopy(packet, 0, framed, 4, length);
            offset = 0;
            available = length + 4;
            return true;
        }

        @Override
        public synchronized void close() throws IOException {
            if (closed) return;
            closed = true;
            tunInput.close();
        }
    }
}
