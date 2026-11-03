package ru.birdiecode.ssh2socks4android;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.Collections;

import org.junit.Test;

public final class VpnPacketRouterTest {
    @Test
    public void dispatchesPacketOnlyToLongestPrefixOwner() throws Exception {
        VpnPacketRouter router = new VpnPacketRouter();
        ByteArrayOutputStream defaultTunnel = new ByteArrayOutputStream();
        ByteArrayOutputStream siteTunnel = new ByteArrayOutputStream();
        router.attach("default", 0, Collections.singletonList("0.0.0.0/0"),
                VpnPacketRouter.framedWriter(defaultTunnel));
        router.attach("site", 0, Collections.singletonList("10.50.0.0/16"),
                VpnPacketRouter.framedWriter(siteTunnel));

        byte[] external = ipv4(1, 1, 1, 1);
        byte[] internal = ipv4(10, 50, 4, 8);
        assertTrue(router.route(external));
        assertTrue(router.route(internal));

        assertArrayEquals(external, decodeSingleFrame(defaultTunnel.toByteArray()));
        assertArrayEquals(internal, decodeSingleFrame(siteTunnel.toByteArray()));
    }

    @Test
    public void unmatchedPacketsAreDroppedAndDetachDoesNotAffectOtherRoutes() throws Exception {
        VpnPacketRouter router = new VpnPacketRouter();
        ByteArrayOutputStream siteTunnel = new ByteArrayOutputStream();
        router.attach("site", 0, Collections.singletonList("10.0.0.0/8"),
                VpnPacketRouter.framedWriter(siteTunnel));

        assertFalse(router.route(ipv4(192, 168, 1, 2)));
        router.attach("backup", 0, Collections.singletonList("172.16.0.0/12"),
                VpnPacketRouter.framedWriter(new ByteArrayOutputStream()));
        router.detach("site");
        assertTrue(router.route(ipv4(172, 16, 8, 2)));
        assertFalse(router.route(ipv4(10, 1, 2, 3)));
    }

    private static byte[] decodeSingleFrame(byte[] framed) {
        int length = ((framed[0] & 0xff) << 24) | ((framed[1] & 0xff) << 16)
                | ((framed[2] & 0xff) << 8) | (framed[3] & 0xff);
        org.junit.Assert.assertEquals(2, framed[7]);
        byte[] packet = new byte[length - 4];
        System.arraycopy(framed, 8, packet, 0, length - 4);
        return packet;
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
}
