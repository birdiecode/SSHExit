package ru.birdiecode.ssh2socks4android;

import java.io.IOException;
import java.net.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;
import static org.junit.Assert.*;

public class SshTransportSocketFactoryTest {
    @Test(timeout=5000) public void createsDescriptorAndProtectsBeforeConnecting() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            AtomicReference<Socket> protectedSocket = new AtomicReference<>();
            SshTransportSocketFactory factory = new SshTransportSocketFactory(socket -> {
                assertTrue("Native socket must exist before protect", socket.isBound());
                assertTrue(socket.getLocalPort() > 0);
                assertFalse("Protect must run before TCP connect", socket.isConnected());
                protectedSocket.set(socket);
                return true;
            }, 1000);
            try (Socket client = factory.createSocket(listener.getInetAddress().getHostAddress(), listener.getLocalPort());
                 Socket accepted = listener.accept()) {
                assertSame(client, protectedSocket.get());
                client.getOutputStream().write(42);
                assertEquals(42, accepted.getInputStream().read());
            }
        }
    }
    @Test(timeout=5000) public void failedProtectionClosesSocketAndNeverConnects() throws Exception {
        AtomicReference<Socket> attempted = new AtomicReference<>();
        SshTransportSocketFactory factory = new SshTransportSocketFactory(socket -> {
            attempted.set(socket); return false;
        }, 1000);
        try {
            factory.createSocket("127.0.0.1", 1);
            fail("Protection rejection must abort");
        } catch (SshTransportSocketFactory.ProtectionException expected) {
            assertTrue(attempted.get().isClosed());
            assertFalse(attempted.get().isConnected());
            assertTrue(SshTransportSocketFactory.isProtectionFailure(new IOException("SSH wrapper", expected)));
            assertTrue(SshTransportSocketFactory.isProtectionFailure(new IOException(expected.toString())));
        }
    }
    @Test(timeout=5000) public void socksSocketDoesNotRequireVpnProtection() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             Socket client = new SshTransportSocketFactory(null, 1000).createSocket(
                     listener.getInetAddress().getHostAddress(), listener.getLocalPort());
             Socket accepted = listener.accept()) {
            assertTrue(client.isConnected());
        }
    }
}
