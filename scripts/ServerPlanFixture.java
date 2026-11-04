package ru.birdiecode.ssh2socks4android;

/** Compiles with production shell generation for isolated Linux network tests. */
public final class ServerPlanFixture {
    public static void main(String[] args) throws Exception {
        int unit = Integer.parseInt(args[0]);
        Profile p = new Profile();
        p.vpnIpv4 = true; p.vpnIpv6 = true;
        p.vpnExternalInterface = "wan0";
        String[] ip6 = TunAddressPlan.ipv6(unit, "fd42:5353::/64");
        String[] ip4 = TunAddressPlan.ipv4(unit);
        System.out.println("# CLIENT4=" + ip4[1]);
        System.out.println("# CLIENT6=" + ip6[1]);
        System.out.print(ServerTunConfiguration.build(p, "tun" + unit, args[1], 1400, ip6));
    }
}
