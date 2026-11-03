package ru.birdiecode.ssh2socks4android;

import java.io.*;
import java.net.SocketTimeoutException;
import java.util.Random;
import java.util.concurrent.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class SshStreamSocketTest {
    @Test(timeout=5000) public void silentJumpStreamTimesOutRepeatedlyThenRecovers() throws Exception {
        try (PipedInputStream pipe = new PipedInputStream();
             PipedOutputStream peer = new PipedOutputStream(pipe);
             SshStreamSocket socket = new SshStreamSocket(pipe, new ByteArrayOutputStream())) {
            socket.setSoTimeout(40);
            for (int i = 0; i < 3; i++) {
                long started = System.nanoTime();
                try { socket.getInputStream().read(); fail("Silent peer did not time out"); }
                catch (SocketTimeoutException expected) {
                    assertTrue("Timeout fired too early", System.nanoTime() - started >= 40_000_000L);
                }
            }
            peer.write(new byte[]{0, (byte) 255, 42}); peer.flush();
            socket.setSoTimeout(1000);
            assertEquals(0, socket.getInputStream().read());
            assertEquals(255, socket.getInputStream().read());
            assertEquals(42, socket.getInputStream().read());
            peer.close();
            assertEquals(-1, socket.getInputStream().read());
        }
    }

    @Test(timeout=5000) public void preservesPacketBytesAcrossBoundedBufferWrapAndEof() throws Exception {
        byte[] expected = new byte[300_000];
        new Random(123).nextBytes(expected);
        try (SshStreamSocket socket = new SshStreamSocket(new ByteArrayInputStream(expected), new ByteArrayOutputStream())) {
            socket.setSoTimeout(1000);
            ByteArrayOutputStream actual = new ByteArrayOutputStream();
            byte[] chunk = new byte[7919];
            int count;
            while ((count = socket.getInputStream().read(chunk)) != -1) actual.write(chunk, 0, count);
            assertArrayEquals(expected, actual.toByteArray());
        }
    }

    @Test(timeout=5000) public void closeUnblocksAnInfiniteReadAndIsIdempotent() throws Exception {
        PipedInputStream pipe = new PipedInputStream();
        try (PipedOutputStream peer = new PipedOutputStream(pipe);
             SshStreamSocket socket = new SshStreamSocket(pipe, new ByteArrayOutputStream())) {
            CountDownLatch entered = new CountDownLatch(1);
            FutureTask<Boolean> result = new FutureTask<>(() -> {
                entered.countDown();
                try { socket.getInputStream().read(); return false; }
                catch (IOException closed) { return true; }
            });
            Thread waiter = new Thread(result); waiter.setDaemon(true); waiter.start();
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            socket.close(); socket.close();
            assertTrue(result.get(1, TimeUnit.SECONDS));
            assertTrue(socket.isClosed());
        }
    }

    @Test(timeout=5000) public void drainsBufferedDataBeforeReportingTransportFailure() throws Exception {
        InputStream failing = new InputStream() {
            boolean sent;
            @Override public int read() throws IOException { throw new IOException("transport failed"); }
            @Override public int read(byte[] bytes, int offset, int length) throws IOException {
                if (sent) throw new IOException("transport failed");
                sent = true; bytes[offset] = 7; return 1;
            }
        };
        try (SshStreamSocket socket = new SshStreamSocket(failing, new ByteArrayOutputStream())) {
            socket.setSoTimeout(1000);
            assertEquals(7, socket.getInputStream().read());
            try { socket.getInputStream().read(); fail("Transport failure was hidden"); }
            catch (IOException expected) { assertEquals("transport failed", expected.getMessage()); }
        }
    }
}
