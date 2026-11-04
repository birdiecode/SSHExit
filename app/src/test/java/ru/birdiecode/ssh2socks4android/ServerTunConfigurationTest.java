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

    @Test public void previewIsTheExactAppliedScriptAndAuditListsItsNftRules() {
        Profile p = new Profile();
        p.vpnIpv4 = true; p.vpnIpv6 = true;
        p.vpnExternalInterface = "ens3"; p.vpnMtu = 1420;
        String[] ipv6 = {"fd00::1", "fd00::2"};
        String preview = ServerTunConfiguration.preview(p, "tun123", "ssh2socks_012345abcdef", ipv6);
        assertEquals(preview, ServerTunConfiguration.build(p, "tun123", "ssh2socks_012345abcdef", 1420, ipv6));
        String applied = ServerTunConfiguration.appliedDescription("nft", p, "tun123", "ssh2socks_012345abcdef", ipv6);
        String actualRules = preview.substring(preview.indexOf("add table inet $TABLE"),
                preview.indexOf("\nEOF"))
                .replace("$TABLE", "ssh2socks_012345abcdef").replace("$IF", "tun123").replace("$WAN", "ens3");
        assertEquals(actualRules, applied);
        assertTrue(applied.contains("oifname \"ens3\" ip saddr 10.0.1.238 masquerade"));
    }

    @Test public void disabledChangesAreAbsentFromServerPlan() {
        Profile p = new Profile();
        p.vpnIpv4 = true; p.vpnIpv6 = true; p.vpnExternalInterface = "eth0";
        p.serverManageIpv4Forwarding = false; p.serverManageIpv6Forwarding = false;
        p.serverNatIpv4 = false; p.serverAcceptOutbound = false; p.serverAcceptReturn = false;
        String script = ServerTunConfiguration.preview(p, "tun123", "ssh2socks_012345abcdef",
                new String[]{"fd00::1", "fd00::2"});
        assertFalse(script.contains("masquerade"));
        assertFalse(script.contains("add rule"));
        assertFalse(script.contains("printf '1"));
        assertTrue(script.contains("automatic change was not approved"));
        assertFalse(script.contains("echo SSHEXIT_APPLIED:forward4"));
        assertFalse(script.contains("echo SSHEXIT_APPLIED:forward6"));
    }

    @Test public void filterDirectionsCanBeChangedIndependently() {
        Profile p = new Profile();
        p.vpnIpv4 = true; p.vpnIpv6 = false; p.vpnExternalInterface = "eth0";
        for (int flags = 0; flags < 8; flags++) {
            p.serverNatIpv4 = (flags & 1) != 0;
            p.serverAcceptOutbound = (flags & 2) != 0;
            p.serverAcceptReturn = (flags & 4) != 0;
            String script = ServerTunConfiguration.preview(p, "tun123", "ssh2socks_012345abcdef",
                    new String[]{"fd00::1", "fd00::2"});
            assertEquals(p.serverNatIpv4, script.contains("masquerade"));
            assertEquals(p.serverAcceptOutbound, script.contains("oifname \"$WAN\" accept"));
            assertEquals(p.serverAcceptReturn, script.contains("ct state established,related accept"));
            assertTrue(script.indexOf("echo SSHEXIT_APPLIED:nft") > script.indexOf("\nEOF"));
            assertTrue(script.contains("trap cleanup EXIT"));
            assertTrue(script.contains("timeout 60 sh -c"));
            assertFalse(script.contains("printf '0"));
            assertFalse(script.contains("route replace"));
            assertTrue(script.contains("SSHEXIT_CLEANUP_FAILED"));
        }
    }

    @Test public void reconnectCanUseFreshTunWithTheSameClientAddressSlot() {
        Profile p = new Profile(); p.vpnExternalInterface = "ens3";
        String[] ipv6 = {"fd00::1","fd00::2"};
        String first = ServerTunConfiguration.build(p, "tun1000001", "ssh2socks_012345abcdef", 1400, ipv6, 1000001);
        String next = ServerTunConfiguration.build(p, "tun1000002", "ssh2socks_112345abcdef", 1400, ipv6, 1000001);
        String client = TunAddressPlan.ipv4(1000001)[1];
        assertTrue(first.contains("ip saddr " + client + " masquerade"));
        assertTrue(next.contains("ip saddr " + client + " masquerade"));
        assertFalse(next.contains("ip saddr " + TunAddressPlan.ipv4(1000002)[1] + " masquerade"));
        assertEquals(next, ServerTunConfiguration.preview(p, "tun1000002", "ssh2socks_112345abcdef", ipv6, 1000001));
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
