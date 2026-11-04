package ru.birdiecode.ssh2socks4android;

import java.net.InetAddress;

/** Each TUN number owns one disjoint /30 IPv4 block and a pair of IPv6 /128s. */
final class TunAddressPlan {
    static final int FIRST_UNIT = 1_000_000;
    static final int UNIT_COUNT = 1_000_000;

    static String[] ipv4(int unit) {
        if (unit < 1 || unit >= (1 << 22)) throw new IllegalArgumentException("Invalid TUN address slot");
        int block = 0x0a000000 | (unit << 2);
        return new String[]{ipv4Text(block + 1), ipv4Text(block + 2)};
    }

    static int unit(String interfaceName) {
        if (interfaceName == null || !interfaceName.matches("tun[0-9]{1,7}"))
            throw new IllegalArgumentException("Invalid server TUN interface");
        int unit = Integer.parseInt(interfaceName.substring(3));
        ipv4(unit);
        return unit;
    }

    static String[] ipv6(int unit, String prefix) throws Exception {
        ipv4(unit);
        if (prefix == null || prefix.isEmpty()) prefix = "fd53:5353:5353::/64";
        String canonical = VpnRouteTable.normalizePrefix(prefix);
        int slash = canonical.lastIndexOf('/');
        if (!canonical.contains(":") || Integer.parseInt(canonical.substring(slash + 1)) > 64)
            throw new IllegalArgumentException("IPv6 prefix must be /64 or wider");
        byte[] address = InetAddress.getByName(canonical.substring(0, slash)).getAddress();
        long suffix = ((long) unit) << 2;
        for (int i = 15; i >= 8; i--) { address[i] = (byte) suffix; suffix >>>= 8; }
        address[15] |= 1;
        String server = InetAddress.getByAddress(address).getHostAddress();
        address[15] = (byte) ((address[15] & 0xfc) | 2);
        return new String[]{server, InetAddress.getByAddress(address).getHostAddress()};
    }

    private static String ipv4Text(int value) {
        return ((value >>> 24) & 255) + "." + ((value >>> 16) & 255) + "."
                + ((value >>> 8) & 255) + "." + (value & 255);
    }
}
