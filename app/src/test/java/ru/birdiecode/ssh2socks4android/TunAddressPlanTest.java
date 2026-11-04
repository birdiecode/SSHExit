package ru.birdiecode.ssh2socks4android;

import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import static org.junit.Assert.*;

public class TunAddressPlanTest {
    @Test public void addressPairsDoNotOverlapAcrossClientsOrRoles() throws Exception {
        Set<String> v4 = new HashSet<>(), v6 = new HashSet<>();
        for (int unit = TunAddressPlan.FIRST_UNIT; unit < TunAddressPlan.FIRST_UNIT + 10000; unit++) {
            for (String a : TunAddressPlan.ipv4(unit)) assertTrue("IPv4 collision: " + a, v4.add(a));
            for (String a : TunAddressPlan.ipv6(unit, "2001:db8:1234::/64"))
                assertTrue("IPv6 collision: " + a, v6.add(a));
        }
    }
    @Test public void firstAndLastSlotsStayInTheirIpv4Blocks() {
        assertArrayEquals(new String[]{"10.0.0.5", "10.0.0.6"}, TunAddressPlan.ipv4(1));
        assertArrayEquals(new String[]{"10.255.255.253", "10.255.255.254"}, TunAddressPlan.ipv4((1<<22)-1));
    }
    @Test public void rejectsOutOfRangeAndUnsafeTunNames() {
        for (String name : new String[]{"tun0","tun4194304","tun-1","tun1;id","eth0"}) {
            try { TunAddressPlan.unit(name); fail(name); } catch (IllegalArgumentException expected) {}
        }
    }
    @Test public void configuredIpv6PrefixIsRetainedAndEachClientHasAnIndependentPair() throws Exception {
        String[] a = TunAddressPlan.ipv6(1000001, "2001:db8:abcd::/48");
        String[] b = TunAddressPlan.ipv6(1000002, "2001:db8:abcd::/48");
        assertNotEquals(a[0], a[1]); assertNotEquals(a[1], b[1]);
        assertTrue(a[0].startsWith("2001:db8:abcd:"));
        try { TunAddressPlan.ipv6(1, "2001:db8::/96"); fail(); }
        catch (IllegalArgumentException expected) {}
    }
}
