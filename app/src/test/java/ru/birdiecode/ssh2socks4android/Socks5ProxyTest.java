package ru.birdiecode.ssh2socks4android;

import com.jcraft.jsch.GreetingTestSession;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import static org.junit.Assert.*;

public class Socks5ProxyTest {
    @Test(timeout = 10000) public void relaysImmediateGreetingAndClientPayload() throws Exception {
        int port;
        try (ServerSocket reserve = new ServerSocket(0)) { port = reserve.getLocalPort(); }
        Socks5Proxy proxy = new Socks5Proxy(new GreetingTestSession(), port);
        assertFalse(proxy.isRunning());
        proxy.start();
        assertTrue(proxy.isRunning());
        try (Socket client = new Socket("127.0.0.1", port)) {
            client.setSoTimeout(3000);
            DataInputStream input = new DataInputStream(client.getInputStream());
            OutputStream output = client.getOutputStream();
            output.write(new byte[]{5,1,0}); output.flush();
            assertEquals(5, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte());
            output.write(new byte[]{5,1,0,1,127,0,0,1,0,80}); output.flush();
            byte[] reply = new byte[10]; input.readFully(reply);
            assertEquals(5, reply[0]); assertEquals(0, reply[1]);
            byte[] greeting = new byte[12]; input.readFully(greeting);
            assertEquals("SERVER-HELLO", new String(greeting, StandardCharsets.US_ASCII));
            byte[] payload = "payload-through-socks".getBytes(StandardCharsets.US_ASCII);
            output.write(payload); output.flush();
            byte[] echoed = new byte[payload.length]; input.readFully(echoed);
            assertArrayEquals(payload, echoed);
        } finally { proxy.stop(); }
        assertFalse(proxy.isRunning());
        try (ServerSocket rebound = new ServerSocket()) {
            rebound.setReuseAddress(true);
            rebound.bind(new InetSocketAddress("127.0.0.1", port));
        }
    }
}
