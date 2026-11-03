package ru.birdiecode.ssh2socks4android;

import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.*;

public class ServerTunConfigurationTest {
    @Test public void generatedScriptsParseInPosixShell() throws Exception {
        for (int mode = 1; mode <= 3; mode++) {
            Profile p = new Profile();
            p.vpnIpv4 = (mode & 1) != 0;
            p.vpnIpv6 = (mode & 2) != 0;
            p.vpnExternalInterface = "";
            String script = ServerTunConfiguration.build(p, "tun12345",
                    "ssh2socks_012345abcdef", 1400, new String[]{"fd00::1", "fd00::2"});
            assertFalse(script.contains("sudo"));
            assertFalse(script.contains("flush ruleset"));
            Process process = new ProcessBuilder("sh", "-n").redirectErrorStream(true).start();
            process.getOutputStream().write(script.getBytes(StandardCharsets.UTF_8));
            process.getOutputStream().close();
            assertTrue("shell syntax check timed out", process.waitFor(5, TimeUnit.SECONDS));
            assertEquals("invalid shell for mode " + mode, 0, process.exitValue());
        }
    }

    @Test public void rejectsShellMetacharactersInInterface() {
        Profile p = new Profile();
        p.vpnExternalInterface = "eth0;id";
        try {
            ServerTunConfiguration.build(p, "tun123", "ssh2socks_012345abcdef",
                    1400, new String[]{"fd00::1", "fd00::2"});
            fail("Unsafe interface accepted");
        } catch (IllegalArgumentException expected) { }
    }
}
