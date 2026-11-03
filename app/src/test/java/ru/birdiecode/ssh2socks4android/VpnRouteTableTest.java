package ru.birdiecode.ssh2socks4android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

public final class VpnRouteTableTest {
    @Test
    public void choosesLongestMatchingPrefixAcrossConnections() {
        VpnRouteTable routes = new VpnRouteTable();
        routes.replaceConnectionRoutes("default", 0, Collections.singletonList("0.0.0.0/0"));
        routes.replaceConnectionRoutes("corp", 0, Collections.singletonList("10.20.0.0/16"));

        assertEquals("default", routes.selectConnection(ipv4(8, 8, 8, 8)));
        assertEquals("corp", routes.selectConnection(ipv4(10, 20, 7, 9)));
    }

    @Test
    public void choosesHigherExplicitPriorityForEqualPrefix() {
        VpnRouteTable routes = new VpnRouteTable();
        routes.replaceConnectionRoutes("backup", 1, Collections.singletonList("192.168.10.0/24"));
        routes.replaceConnectionRoutes("primary", 5, Collections.singletonList("192.168.10.0/24"));
        assertEquals("primary", routes.selectConnection(ipv4(192, 168, 10, 1)));
    }

    @Test
    public void rejectsEqualPrefixAndPriorityConflictWithoutChangingExistingRoutes() {
        VpnRouteTable routes = new VpnRouteTable();
        routes.replaceConnectionRoutes("one", 3, Collections.singletonList("10.0.0.0/8"));
        try {
            routes.replaceConnectionRoutes("two", 3, Collections.singletonList("10.0.0.0/8"));
            fail("Expected a route conflict");
        } catch (IllegalArgumentException expected) {
            assertEquals("Route conflict for 10.0.0.0/8 at priority 3", expected.getMessage());
        }
        assertEquals("one", routes.selectConnection(ipv4(10, 1, 2, 3)));
    }

    @Test
    public void routesIpv6AndSupportsDefaultPrefix() {
        VpnRouteTable routes = new VpnRouteTable();
        routes.replaceConnectionRoutes("v6-default", 0, Collections.singletonList("::/0"));
        routes.replaceConnectionRoutes("v6-site", 1, Collections.singletonList("2001:db8:1::/48"));

        assertEquals("v6-default", routes.selectConnection(ipv6("2001:db8:ffff::1")));
        assertEquals("v6-site", routes.selectConnection(ipv6("2001:db8:1::25")));
        assertNull(routes.selectConnection(ipv4(1, 1, 1, 1)));
    }

    @Test
    public void removingConnectionLeavesOtherRoutesActive() {
        VpnRouteTable routes = new VpnRouteTable();
        routes.replaceConnectionRoutes("a", 1, Collections.singletonList("10.0.0.0/8"));
        routes.replaceConnectionRoutes("b", 1, Collections.singletonList("172.16.0.0/12"));
        routes.removeConnection("a");

        assertNull(routes.selectConnection(ipv4(10, 1, 1, 1)));
        assertEquals("b", routes.selectConnection(ipv4(172, 16, 1, 2)));
    }

    private static byte[] ipv4(int a, int b, int c, int d) {
        byte[] packet = new byte[20];
        packet[0] = 0x45;
        packet[16] = (byte) a;
        packet[17] = (byte) b;
        packet[18] = (byte) c;
        packet[19] = (byte) d;
        return packet;
    }

    private static byte[] ipv6(String address) {
        try {
            byte[] packet = new byte[40];
            packet[0] = 0x60;
            byte[] bytes = java.net.InetAddress.getByName(address).getAddress();
            System.arraycopy(bytes, 0, packet, 24, 16);
            return packet;
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
