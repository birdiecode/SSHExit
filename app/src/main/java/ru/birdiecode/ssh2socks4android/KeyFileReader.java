package ru.birdiecode.ssh2socks4android;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.util.Arrays;
import java.util.function.BooleanSupplier;

/** Reads at most MAX_BYTES + 1 bytes, even when provider metadata is absent or false. */
final class KeyFileReader {
    static final int MAX_BYTES = 256 * 1024;
    static final class TooLargeException extends IOException {
        TooLargeException() { super("Приватный ключ должен быть не больше 256 КиБ"); }
    }

    static byte[] read(InputStream input, BooleanSupplier cancelled) throws IOException {
        if (input == null) throw new IOException("Key stream unavailable");
        byte[] buffer = new byte[MAX_BYTES + 1];
        int size = 0;
        try {
            while (size < buffer.length) {
                if (cancelled.getAsBoolean() || Thread.currentThread().isInterrupted())
                    throw new InterruptedIOException("Key import cancelled");
                int count = input.read(buffer, size, Math.min(8192, buffer.length - size));
                if (count < 0) break;
                if (count == 0) {
                    int single = input.read();
                    if (single < 0) break;
                    buffer[size++] = (byte) single;
                } else size += count;
                if (size > MAX_BYTES) throw new TooLargeException();
            }
            if (size == 0) throw new IOException("Empty key file");
            if (cancelled.getAsBoolean()) throw new InterruptedIOException("Key import cancelled");
            return Arrays.copyOf(buffer, size);
        } finally { Arrays.fill(buffer, (byte) 0); }
    }
    private KeyFileReader() {}
}
