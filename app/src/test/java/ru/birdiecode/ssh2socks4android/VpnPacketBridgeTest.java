package ru.birdiecode.ssh2socks4android;

import java.io.*;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import org.junit.Test;
import static org.junit.Assert.*;

public class VpnPacketBridgeTest {
    private static final class Device implements VpnPacketBridge.PacketIo {
        final BlockingQueue<byte[]> fromApps = new LinkedBlockingQueue<>(), toApps = new LinkedBlockingQueue<>();
        final AtomicInteger closes = new AtomicInteger();
        final AtomicBoolean fail = new AtomicBoolean();
        volatile boolean closed;
        public int readPacket(byte[] output) throws IOException {
            if (fail.getAndSet(false)) throw new IOException("device failure");
            if (closed) return -1;
            try {
                byte[] packet = fromApps.poll(25, TimeUnit.MILLISECONDS);
                if (packet == null) return 0;
                System.arraycopy(packet, 0, output, 0, packet.length); return packet.length;
            } catch (InterruptedException error) { throw new InterruptedIOException(); }
        }
        public void writePacket(byte[] packet, int offset, int length) throws IOException {
            if (closed) throw new IOException("closed");
            toApps.add(Arrays.copyOfRange(packet, offset, offset + length));
        }
        public void close() { if (!closed) { closed = true; closes.incrementAndGet(); } }
    }
    private static byte[] packet(int tag) {
        byte[] p = new byte[20]; p[0] = 0x45; p[19] = (byte) tag; return p;
    }
    private static byte[] frame(byte[] packet) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeInt(packet.length + 4); output.writeInt(2); output.write(packet); return bytes.toByteArray();
    }
    private static byte[] readPacket(InputStream stream) throws IOException {
        DataInputStream input = new DataInputStream(stream);
        int length = input.readInt(); assertEquals(2, input.readInt());
        byte[] packet = new byte[length - 4]; input.readFully(packet); return packet;
    }
    private static void await(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + 2_000_000_000L;
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue("Condition timed out", condition.getAsBoolean());
    }

    @Test(timeout=5000) public void retainsDeviceAndDropsTrafficAcrossRetryAndNewSshEndpoint() throws Exception {
        Device device = new Device();
        try (VpnPacketBridge bridge = new VpnPacketBridge(device, 1400, 1000001)) {
            device.fromApps.add(packet(1)); await(() -> bridge.droppedPackets() == 1);
            VpnPacketBridge.Endpoint old = bridge.prepareEndpoint(); old.enable();
            device.fromApps.add(packet(2)); assertArrayEquals(packet(2), readPacket(old.outgoing()));
            bridge.block();
            assertEquals(0, device.closes.get());
            assertEquals(-1, old.outgoing().read());
            device.fromApps.add(packet(3)); await(() -> bridge.droppedPackets() == 2);
            VpnPacketBridge.Endpoint next = bridge.prepareEndpoint();
            // Incoming and outgoing data stay blocked while the server is being configured.
            next.incoming().write(frame(packet(4)));
            assertNull(device.toApps.poll(50, TimeUnit.MILLISECONDS));
            device.fromApps.add(packet(5)); await(() -> bridge.droppedPackets() == 3);
            next.enable();
            old.incoming().write(frame(packet(6))); // Old SSH session cannot inject late replies.
            assertNull(device.toApps.poll(50, TimeUnit.MILLISECONDS));
            next.incoming().write(frame(packet(7)));
            assertArrayEquals(packet(7), device.toApps.poll(1, TimeUnit.SECONDS));
            device.fromApps.add(packet(8)); assertArrayEquals(packet(8), readPacket(next.outgoing()));
            assertEquals(1000001, bridge.addressSlot());
            assertEquals(0, device.closes.get());
        }
        assertEquals(1, device.closes.get());
    }

    @Test(timeout=5000) public void sshStreamCloseAndFailedAttemptsNeverCloseSystemTun() throws Exception {
        Device device = new Device();
        VpnPacketBridge bridge = new VpnPacketBridge(device, 1400, 1000002);
        try {
            for (int i = 0; i < 5; i++) {
                VpnPacketBridge.Endpoint endpoint = bridge.prepareEndpoint();
                endpoint.outgoing().close(); endpoint.incoming().close(); bridge.block();
                assertEquals(0, device.closes.get());
                assertEquals(1000002, bridge.addressSlot());
            }
        } finally { bridge.close(); bridge.close(); }
        assertEquals(1, device.closes.get());
    }

    @Test(timeout=5000) public void boundedQueueDoesNotStopDrainingAndBlockDiscardsQueuedFrames() throws Exception {
        Device device = new Device();
        try (VpnPacketBridge bridge = new VpnPacketBridge(device, 1400, 1000003)) {
            VpnPacketBridge.Endpoint endpoint = bridge.prepareEndpoint(); endpoint.enable();
            for (int i=0; i<500; i++) device.fromApps.add(packet(i));
            await(() -> bridge.droppedPackets() >= 436);
            bridge.block();
            assertEquals(-1, endpoint.outgoing().read());
            assertEquals(0, device.closes.get());
        }
    }

    @Test(timeout=5000) public void finalDisconnectWakesSshReaderAndClosesDeviceOnce() throws Exception {
        Device device = new Device();
        VpnPacketBridge bridge = new VpnPacketBridge(device, 1400, 1000004);
        VpnPacketBridge.Endpoint endpoint = bridge.prepareEndpoint();
        FutureTask<Integer> read = new FutureTask<>(() -> endpoint.outgoing().read());
        Thread waiter = new Thread(read); waiter.setDaemon(true); waiter.start();
        bridge.close(); bridge.close();
        assertEquals(-1, (int) read.get(1, TimeUnit.SECONDS));
        assertEquals(1, device.closes.get());
    }

    @Test(timeout=5000) public void localPacketFailureKeepsDescriptorUntilExplicitDisconnect() throws Exception {
        Device device = new Device();
        try (VpnPacketBridge bridge = new VpnPacketBridge(device, 1400, 1000005)) {
            device.fail.set(true);
            await(() -> !bridge.failure().isEmpty());
            assertEquals(0, device.closes.get());
            try { bridge.prepareEndpoint(); fail("Broken device accepted"); } catch (IOException expected) {}
        }
        assertEquals(1, device.closes.get());
    }
}
