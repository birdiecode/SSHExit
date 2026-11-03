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

    /**
     * Reassembles potentially fragmented SSH channel-data writes and emits each
     * complete framed packet as one write to the Android TUN descriptor.
     */
    public static OutputStream removeOpenSshFraming(OutputStream tunOutput, int mtu) {
        if (tunOutput == null) throw new IllegalArgumentException("TUN output is required");
        validateMtu(mtu);
        return new FramedPacketOutputStream(tunOutput, mtu);
    }

    private static final class FramedPacketOutputStream extends OutputStream {
        private final OutputStream tunOutput;
        private final int mtu;
        private final byte[] header = new byte[4];
        private final byte[] packet;
        private int headerOffset;
        private int packetLength = -1;
        private int packetOffset;
        private boolean closed;

        FramedPacketOutputStream(OutputStream tunOutput, int mtu) {
            this.tunOutput = tunOutput;
            this.mtu = mtu;
            this.packet = new byte[mtu];
        }

        @Override
        public synchronized void write(int value) throws IOException {
            byte[] one = new byte[] {(byte) value};
            write(one, 0, 1);
        }

        @Override
        public synchronized void write(byte[] bytes, int offset, int length) throws IOException {
            if (closed) throw new IOException("Stream is closed");
            if (bytes == null) throw new NullPointerException("bytes");
            if (offset < 0 || length < 0 || length > bytes.length - offset) {
                throw new IndexOutOfBoundsException();
            }
            int end = offset + length;
            while (offset < end) {
                if (packetLength < 0) {
                    int count = Math.min(4 - headerOffset, end - offset);
                    System.arraycopy(bytes, offset, header, headerOffset, count);
                    offset += count;
                    headerOffset += count;
                    if (headerOffset == 4) {
                        packetLength = ((header[0] & 0xff) << 24) | ((header[1] & 0xff) << 16)
                                | ((header[2] & 0xff) << 8) | (header[3] & 0xff);
                        if (packetLength <= 0 || packetLength > mtu) {
                            throw new IOException("Invalid SSH TUN packet length: " + packetLength);
                        }
                        packetOffset = 0;
                    }
                } else {
                    int count = Math.min(packetLength - packetOffset, end - offset);
                    System.arraycopy(bytes, offset, packet, packetOffset, count);
                    offset += count;
                    packetOffset += count;
                    if (packetOffset == packetLength) {
                        tunOutput.write(packet, 0, packetLength);
                        tunOutput.flush();
                        packetLength = -1;
                        packetOffset = 0;
                        headerOffset = 0;
                    }
                }
            }
        }

        @Override
        public synchronized void close() throws IOException {
            if (closed) return;
            closed = true;
            try {
                if (headerOffset != 0 || packetLength >= 0) {
                    throw new IOException("SSH TUN channel closed in the middle of a packet");
                }
            } finally {
                tunOutput.close();
            }
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
