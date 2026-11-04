package ru.birdiecode.ssh2socks4android;

import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import java.io.IOException;

/** Sole owner of the Android descriptor; SSH channels only see packet endpoints. */
final class AndroidTunDevice implements VpnPacketBridge.PacketIo {
    private final ParcelFileDescriptor descriptor;
    private volatile boolean closed;

    AndroidTunDevice(ParcelFileDescriptor descriptor) { this.descriptor = descriptor; }

    private int poll(short events) throws ErrnoException {
        StructPollfd fd = new StructPollfd();
        fd.fd = descriptor.getFileDescriptor(); fd.events = events;
        if (Os.poll(new StructPollfd[]{fd}, 250) == 0) return 0;
        if ((fd.revents & (OsConstants.POLLERR | OsConstants.POLLHUP | OsConstants.POLLNVAL)) != 0)
            throw new ErrnoException("TUN poll", OsConstants.EIO);
        return fd.revents & events;
    }

    @Override public int readPacket(byte[] packet) throws IOException {
        if (closed) return -1;
        try {
            if (poll((short) OsConstants.POLLIN) == 0) return 0;
            return Os.read(descriptor.getFileDescriptor(), packet, 0, packet.length);
        } catch (ErrnoException error) {
            if (error.errno == OsConstants.EAGAIN || error.errno == OsConstants.EINTR) return 0;
            throw new IOException("Android TUN read failed", error);
        }
    }

    @Override public void writePacket(byte[] packet, int offset, int length) throws IOException {
        if (closed) throw new IOException("Android TUN closed");
        try {
            if (poll((short) OsConstants.POLLOUT) == 0) return; // Drop under TUN backpressure.
            int written = Os.write(descriptor.getFileDescriptor(), packet, offset, length);
            if (written != length) throw new IOException("Incomplete Android TUN packet write");
        } catch (ErrnoException error) {
            if (error.errno == OsConstants.EAGAIN || error.errno == OsConstants.EINTR) return;
            throw new IOException("Android TUN write failed", error);
        }
    }

    @Override public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        descriptor.close();
    }
}
