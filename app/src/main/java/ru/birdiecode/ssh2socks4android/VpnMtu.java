package ru.birdiecode.ssh2socks4android;

/** Application MTU policy, shared by UI, Android TUN, packet adapters and Linux plans. */
final class VpnMtu {
    static final int DEFAULT = 1400;
    static final int MIN_IPV4 = 576;
    static final int MIN_IPV6 = 1280;
    // Keep the existing UI limit, below the SSH channel's packet-size ceiling.
    static final int MAX = 9000;

    static int minimum(boolean ipv6) { return ipv6 ? MIN_IPV6 : MIN_IPV4; }
    static String hint(boolean ipv6) { return "MTU (" + minimum(ipv6) + "–" + MAX + ")"; }

    static int validate(int mtu, boolean ipv6) {
        if (mtu < minimum(ipv6) || mtu > MAX)
            throw new IllegalArgumentException("MTU должен быть в диапазоне " + minimum(ipv6)
                    + "–" + MAX + (ipv6 ? " при включённом IPv6" : " для IPv4"));
        return mtu;
    }

    static int parse(String text, boolean ipv6) {
        final int mtu;
        try { mtu = Integer.parseInt(text == null ? "" : text.trim()); }
        catch (NumberFormatException error) {
            throw new IllegalArgumentException("MTU должен быть целым числом в диапазоне "
                    + minimum(ipv6) + "–" + MAX);
        }
        return validate(mtu, ipv6);
    }
    private VpnMtu() {}
}
