package ru.birdiecode.ssh2socks4android;

import java.io.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class VpnMtuTest {
    private void rejects(Runnable operation) {
        try { operation.run(); fail("Invalid MTU accepted"); }
        catch (IllegalArgumentException expected) { assertTrue(expected.getMessage().contains("MTU")); }
    }
    @Test public void ipv4BoundariesAndOldConflictValue() {
        for (int mtu : new int[]{576,1000,1280,1400,9000}) assertEquals(mtu, VpnMtu.validate(mtu, false));
        for (int mtu : new int[]{-1,0,575,9001,32768,65535}) rejects(() -> VpnMtu.validate(mtu, false));
    }
    @Test public void ipv6Needs1280ForBothIpv6OnlyAndDualStack() {
        for (int mtu : new int[]{1280,1400,9000}) assertEquals(mtu, VpnMtu.validate(mtu, true));
        for (int mtu : new int[]{576,1000,1279,9001}) rejects(() -> VpnMtu.validate(mtu, true));
    }
    @Test public void parsingAndHintsUseTheSamePolicy() {
        assertEquals(1000, VpnMtu.parse(" 1000 ", false));
        assertEquals(1280, VpnMtu.parse("1280", true));
        for (String text : new String[]{null,"","1.5","abc","2147483648"})
            rejects(() -> VpnMtu.parse(text, false));
        rejects(() -> VpnMtu.parse("1000", true));
        assertEquals("MTU (576–9000)", VpnMtu.hint(false));
        assertEquals("MTU (1280–9000)", VpnMtu.hint(true));
    }
    @Test public void serverPreviewMatchesPacketAdaptersForEveryAddressMode() throws Exception {
        for (int mode : new int[]{1,2,3}) {
            Profile profile = new Profile();
            profile.vpnIpv4 = (mode & 1) != 0; profile.vpnIpv6 = (mode & 2) != 0;
            profile.vpnExternalInterface = "eth0";
            for (int mtu : new int[]{575,576,1000,1279,1280,1400,9000,9001,32768,65535}) {
                profile.vpnMtu = mtu;
                boolean valid = mtu >= VpnMtu.minimum(profile.vpnIpv6) && mtu <= VpnMtu.MAX;
                Runnable server = () -> ServerTunConfiguration.preview(profile, "tun1000001",
                        "ssh2socks_012345abcdef", new String[]{"fd00::1","fd00::2"}, 1000001);
                Runnable packets = () -> TunPacketStreams.removeOpenSshFraming(
                        new ByteArrayOutputStream(), profile.vpnMtu, profile.vpnIpv6);
                Runnable input = () -> TunPacketStreams.addOpenSshFraming(
                        new ByteArrayInputStream(new byte[0]), profile.vpnMtu, profile.vpnIpv6);
                if (valid) { server.run(); packets.run(); input.run(); }
                else { rejects(server); rejects(packets); rejects(input); }
            }
        }
    }
    @Test public void bridgeUsesSamePolicyAndDoesNotStartIoOnInvalidMtu() throws Exception {
        for (boolean ipv6 : new boolean[]{false,true}) {
            for (int mtu : new int[]{575,576,1000,1280,9000,9001}) {
                final int[] reads = {0};
                VpnPacketBridge.PacketIo io = new VpnPacketBridge.PacketIo() {
                    public int readPacket(byte[] bytes) throws IOException {
                        reads[0]++;
                        try { Thread.sleep(5); } catch (InterruptedException e) { throw new InterruptedIOException(); }
                        return 0;
                    }
                    public void writePacket(byte[] bytes,int offset,int size) {}
                    public void close() {}
                };
                if (mtu >= VpnMtu.minimum(ipv6) && mtu <= VpnMtu.MAX) {
                    try (VpnPacketBridge bridge = new VpnPacketBridge(io, mtu, 1000001, ipv6)) {
                        assertEquals(mtu, bridge.mtu());
                    }
                } else {
                    rejects(() -> new VpnPacketBridge(io, mtu, 1000001, ipv6));
                    assertEquals(0, reads[0]);
                }
            }
        }
    }
    @Test public void ipv4Mtu1000AndJumboPacketsRoundTrip() throws Exception {
        for (int mtu : new int[]{1000,9000}) {
            byte[] packet = new byte[mtu]; packet[0] = 0x45; packet[mtu-1] = 7;
            InputStream framed = TunPacketStreams.addOpenSshFraming(new ByteArrayInputStream(packet), mtu, false);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            TunPacketStreams.copyOpenSshFramesToTun(framed, output, mtu, false);
            assertArrayEquals(packet, output.toByteArray());
        }
    }
}
