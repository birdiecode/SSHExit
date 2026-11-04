package ru.birdiecode.ssh2socks4android;

import java.io.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;
import static org.junit.Assert.*;

public class KeyFileReaderTest {
    @Test public void acceptsExactLimitAndPreservesBytes() throws Exception {
        byte[] source = new byte[KeyFileReader.MAX_BYTES];
        source[0] = 7; source[source.length - 1] = 9;
        assertArrayEquals(source, KeyFileReader.read(new ByteArrayInputStream(source), () -> false));
    }
    @Test public void oversizedUnknownLengthStreamStopsAfterLimitPlusOne() throws Exception {
        AtomicInteger consumed = new AtomicInteger();
        InputStream endless = new InputStream() {
            public int read() { consumed.incrementAndGet(); return 1; }
            public int read(byte[] buffer, int offset, int length) {
                java.util.Arrays.fill(buffer, offset, offset + length, (byte) 1);
                consumed.addAndGet(length); return length;
            }
        };
        try { KeyFileReader.read(endless, () -> false); fail("Oversized key accepted"); }
        catch (KeyFileReader.TooLargeException expected) {
            assertEquals(KeyFileReader.MAX_BYTES + 1, consumed.get());
        }
    }
    @Test public void emptyAndUnavailableStreamsAreRejected() throws Exception {
        for (InputStream input : new InputStream[]{null, new ByteArrayInputStream(new byte[0])}) {
            try { KeyFileReader.read(input, () -> false); fail("Empty key accepted"); }
            catch (IOException expected) {}
        }
    }
    @Test public void cancellationStopsBeforeReadingOrAfterAPartialRead() throws Exception {
        AtomicInteger reads = new AtomicInteger();
        InputStream input = new InputStream() {
            public int read() { reads.incrementAndGet(); return 1; }
        };
        try { KeyFileReader.read(input, () -> true); fail("Ignored cancellation"); }
        catch (InterruptedIOException expected) { assertEquals(0, reads.get()); }
        try { KeyFileReader.read(input, () -> reads.get() > 0); fail("Ignored partial cancellation"); }
        catch (InterruptedIOException expected) { assertTrue(reads.get() > 0); }
    }
    @Test public void readFailurePropagatesAndScratchBufferIsWiped() throws Exception {
        final byte[][] scratch = new byte[1][];
        InputStream input = new InputStream() {
            public int read() throws IOException { throw new IOException("read failed"); }
            public int read(byte[] bytes, int offset, int length) throws IOException {
                scratch[0] = bytes; bytes[offset] = 42; throw new IOException("read failed");
            }
        };
        try { KeyFileReader.read(input, () -> false); fail("Ignored read failure"); }
        catch (IOException expected) {
            for (byte value : scratch[0]) assertEquals(0, value);
        }
    }
    @Test public void zeroLengthReadDoesNotBusyLoop() throws Exception {
        InputStream input = new InputStream() {
            boolean read;
            public int read(byte[] bytes, int offset, int length) { return read ? -1 : 0; }
            public int read() { read = true; return 7; }
        };
        assertArrayEquals(new byte[]{7}, KeyFileReader.read(input, () -> false));
    }
}
