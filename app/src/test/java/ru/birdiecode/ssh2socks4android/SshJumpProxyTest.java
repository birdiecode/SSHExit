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
}
