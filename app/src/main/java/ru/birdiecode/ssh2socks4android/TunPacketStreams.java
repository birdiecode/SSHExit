package ru.birdiecode.ssh2socks4android;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Internal packet queue framing: uint32 length, OpenBSD AF, then the IP datagram.
 * OpenSshTunChannel removes/restores the queue length at the SSH boundary.
 * CHANNEL_DATA carries exactly one AF + IP datagram; its SSH string supplies the wire length.
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
        OutputStream decoder = removeOpenSshFraming(tunOutput, mtu);
        byte[] buffer = new byte[mtu + 8];
        int count;
        while ((count = channelInput.read(buffer)) >= 0) {
            if (count > 0) decoder.write(buffer, 0, count);
        }
        ((FramedPacketOutputStream) decoder).finish();
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
        private final byte[] header = new byte[8];
        private final byte[] packet;
        private int headerOffset;
        private int packetLength = -1;
        private int packetOffset;
        private int expectedVersion;
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
                    int count = Math.min(8 - headerOffset, end - offset);
                    System.arraycopy(bytes, offset, header, headerOffset, count);
                    offset += count;
                    headerOffset += count;
                    if (headerOffset == 8) {
                        packetLength = ((header[0] & 0xff) << 24) | ((header[1] & 0xff) << 16)
                                | ((header[2] & 0xff) << 8) | (header[3] & 0xff);
                        if (packetLength <= 4 || packetLength > mtu + 4) {
                            throw new IOException("Invalid SSH TUN packet length: " + packetLength);
                        }
                        int family = ((header[4] & 255) << 24) | ((header[5] & 255) << 16)
                                | ((header[6] & 255) << 8) | (header[7] & 255);
                        if (family != 2 && family != 24) throw new IOException("Invalid SSH TUN address family");
                        expectedVersion = family == 2 ? 4 : 6;
                        packetLength -= 4;
                        packetOffset = 0;
                    }
                } else {
                    int count = Math.min(packetLength - packetOffset, end - offset);
                    System.arraycopy(bytes, offset, packet, packetOffset, count);
                    offset += count;
                    packetOffset += count;
                    if (packetOffset == packetLength) {
                        if ((packet[0] >>> 4 & 15) != expectedVersion)
                            throw new IOException("SSH TUN address family does not match packet");
                        tunOutput.write(packet, 0, packetLength);
                        tunOutput.flush();
                        packetLength = -1;
                        packetOffset = 0;
                        headerOffset = 0;
                    }
                }
            }
        }

        synchronized void finish() throws IOException {
            if (headerOffset != 0 || packetLength >= 0)
                throw new EOFException("SSH TUN channel closed in the middle of a packet");
        }

        @Override public synchronized void close() throws IOException {
            if (closed) return;
            closed = true;
            try { finish(); } finally { tunOutput.close(); }
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
            this.framed = new byte[mtu + 8];
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
            int version = (packet[0] >>> 4) & 15;
            if (version != 4 && version != 6) throw new IOException("Unsupported TUN packet version");
            int framedLength = length + 4;
            framed[0] = (byte) (framedLength >>> 24);
            framed[1] = (byte) (framedLength >>> 16);
            framed[2] = (byte) (framedLength >>> 8);
            framed[3] = (byte) framedLength;
            framed[4] = framed[5] = framed[6] = 0;
            framed[7] = (byte) (version == 4 ? 2 : 24);
            System.arraycopy(packet, 0, framed, 8, length);
            offset = 0;
            available = length + 8;
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
