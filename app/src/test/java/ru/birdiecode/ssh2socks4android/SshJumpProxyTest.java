package ru.birdiecode.ssh2socks4android;

import com.jcraft.jsch.GreetingTestSession;
import java.io.DataInputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import static org.junit.Assert.*;

public class SshJumpProxyTest {
    @Test(timeout=5000) public void forwardsGreetingAndAppliesReadTimeoutToTheJumpStream() throws Exception {
        SshJumpProxy proxy = new SshJumpProxy(new GreetingTestSession());
        try {
            proxy.connect(null, "2001:db8::1", 22, 1000);
            assertNotNull(proxy.getSocket());
            proxy.getSocket().setSoTimeout(1000);
            byte[] greeting = new byte[12];
            new DataInputStream(proxy.getInputStream()).readFully(greeting);
            assertEquals("SERVER-HELLO", new String(greeting, StandardCharsets.US_ASCII));
            proxy.getOutputStream().write(42); proxy.getOutputStream().flush();
            assertEquals(42, proxy.getInputStream().read());
            proxy.getSocket().setSoTimeout(40);
            try { proxy.getInputStream().read(); fail("ProxyJump did not honor JSch SO_TIMEOUT"); }
            catch (SocketTimeoutException expected) { }
            proxy.getSocket().close();
            assertTrue(proxy.getSocket().isClosed());
        } finally { proxy.close(); }
        proxy.close();
    }

    @org.junit.Test public void classifiesJumpChannelRejectionAndReachabilitySeparately() throws Exception {
        for (int reason : new int[]{1,2,3,4,-1}) {
            com.jcraft.jsch.Session session = org.mockito.Mockito.mock(com.jcraft.jsch.Session.class);
            com.jcraft.jsch.ChannelDirectTCPIP channel = org.mockito.Mockito.mock(com.jcraft.jsch.ChannelDirectTCPIP.class);
            org.mockito.Mockito.when(session.isConnected()).thenReturn(true);
            org.mockito.Mockito.when(session.openChannel("direct-tcpip")).thenReturn(channel);
            org.mockito.Mockito.when(channel.getInputStream()).thenReturn(new java.io.ByteArrayInputStream(new byte[0]));
            org.mockito.Mockito.when(channel.getOutputStream()).thenReturn(new java.io.ByteArrayOutputStream());
            org.mockito.Mockito.when(channel.getExitStatus()).thenReturn(reason);
            org.mockito.Mockito.doThrow(new com.jcraft.jsch.JSchException("channel is not opened."))
                    .when(channel).connect(1000);
            SshJumpProxy proxy = new SshJumpProxy(session);
            try { proxy.connect(null, "::1", 22, 1000); fail("Failure accepted"); }
            catch (ConnectionFailurePolicy.Failure error) {
                assertEquals(reason == 1 || reason == 3
                        ? ConnectionFailurePolicy.Kind.CONFIGURATION
                        : ConnectionFailurePolicy.Kind.TEMPORARY_NETWORK, error.kind);
            } finally { proxy.close(); }
        }
    }
    @org.junit.Test public void disconnectedJumpIsATemporaryFailure() throws Exception {
        com.jcraft.jsch.Session session = org.mockito.Mockito.mock(com.jcraft.jsch.Session.class);
        SshJumpProxy proxy = new SshJumpProxy(session);
        try { proxy.connect(null, "host", 22, 1000); fail("Failure accepted"); }
        catch (ConnectionFailurePolicy.Failure error) {
            assertEquals(ConnectionFailurePolicy.Kind.TEMPORARY_NETWORK, error.kind);
        }
    }
}
