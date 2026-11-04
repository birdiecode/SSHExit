package ru.birdiecode.ssh2socks4android;

import com.jcraft.jsch.Session;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.function.BooleanSupplier;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class Socks5ResourceLimitsTest {
    private int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) { return socket.getLocalPort(); }
    }
    private Socket connect(int port) throws IOException {
        Socket socket = new Socket("127.0.0.1", port); socket.setSoTimeout(2000); return socket;
    }
    private void await(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + 3_000_000_000L;
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue("Condition timed out", condition.getAsBoolean());
    }
    private void close(List<Socket> sockets) {
        for (Socket socket : sockets) try { socket.close(); } catch (IOException ignored) {}
    }

    @Test(timeout=15000) public void excessClientIsClosedAndCapacityReturnsAfterDisconnect() throws Exception {
        int port = freePort();
        Socks5Proxy proxy = new Socks5Proxy(mock(Session.class), port);
        List<Socket> sockets = new ArrayList<>();
        proxy.start();
        try {
            for (int i = 0; i < Socks5Proxy.MAX_CLIENTS_PER_PROXY; i++) sockets.add(connect(port));
            await(() -> proxy.activeClientCount() == Socks5Proxy.MAX_CLIENTS_PER_PROXY);
            try (Socket rejected = connect(port)) { assertEquals(-1, rejected.getInputStream().read()); }
            assertTrue(proxy.isRunning());
            assertEquals(Socks5Proxy.MAX_CLIENTS_PER_PROXY, proxy.activeClientCount());
            sockets.get(0).close();
            await(() -> proxy.activeClientCount() == Socks5Proxy.MAX_CLIENTS_PER_PROXY - 1);
            Socket next = connect(port); sockets.add(next);
            await(() -> proxy.activeClientCount() == Socks5Proxy.MAX_CLIENTS_PER_PROXY);
            // Prove that the replacement was admitted, rather than only observing TCP accept.
            next.getOutputStream().write(new byte[]{5, 1, 0});
            assertEquals(5, next.getInputStream().read());
            assertEquals(0, next.getInputStream().read());
        } finally { close(sockets); proxy.stop(); }
        await(() -> proxy.activeClientCount() == 0 && Socks5Proxy.globalClientCount() == 0);
    }

    @Test(timeout=15000) public void globalLimitAndThreadBudgetApplyAcrossProxies() throws Exception {
        int aPort = freePort(), bPort = freePort(), cPort = freePort();
        Socks5Proxy a = new Socks5Proxy(mock(Session.class), aPort);
        Socks5Proxy b = new Socks5Proxy(mock(Session.class), bPort);
        Socks5Proxy c = new Socks5Proxy(mock(Session.class), cPort);
        List<Socket> sockets = new ArrayList<>();
        a.start(); b.start(); c.start();
        try {
            for (int i=0; i<Socks5Proxy.MAX_CLIENTS_PER_PROXY; i++) {
                sockets.add(connect(aPort)); sockets.add(connect(bPort));
            }
            await(() -> Socks5Proxy.globalClientCount() == Socks5Proxy.MAX_CLIENTS_GLOBAL);
            try (Socket rejected = connect(cPort)) { assertEquals(-1, rejected.getInputStream().read()); }
            assertEquals(0, c.activeClientCount());
            assertTrue(Socks5Proxy.workerThreadCount() <= 2 * Socks5Proxy.MAX_CLIENTS_GLOBAL);
            a.stop();
            await(() -> a.activeClientCount() == 0);
            assertTrue(b.isRunning());
            Socket admitted = connect(cPort); sockets.add(admitted);
            admitted.getOutputStream().write(new byte[]{5, 1, 0});
            assertEquals(5, admitted.getInputStream().read());
            assertEquals(0, admitted.getInputStream().read());
        } finally { close(sockets); a.stop(); b.stop(); c.stop(); }
        await(() -> Socks5Proxy.globalClientCount() == 0);
    }

    @Test(timeout=10000) public void stopClosesBlockedHandshakeAndAllowsRestart() throws Exception {
        int port = freePort(); Socks5Proxy proxy = new Socks5Proxy(mock(Session.class), port);
        proxy.start();
        try (Socket socket = connect(port)) {
            await(() -> proxy.activeClientCount() == 1);
            proxy.stop();
            assertEquals(-1, socket.getInputStream().read());
            await(() -> proxy.activeClientCount() == 0);
            proxy.start();
            assertTrue(proxy.isRunning());
        } finally { proxy.stop(); }
        await(() -> Socks5Proxy.globalClientCount() == 0);
    }
}
