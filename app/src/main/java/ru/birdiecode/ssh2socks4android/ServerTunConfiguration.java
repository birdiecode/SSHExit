package ru.birdiecode.ssh2socks4android;

/** Owns server shell generation; never invokes privilege escalation. */
final class ServerTunConfiguration {
    private static final String VPN_IPV4_SERVER = "10.253.0.1";
    private static final String VPN_IPV4_CLIENT = "10.253.0.2";
    static String build(Profile profile, String interfaceName, String table,
                                        int mtu, String[] ipv6) {
        String wan = profile.vpnExternalInterface == null ? "" : profile.vpnExternalInterface.trim();
        if (!interfaceName.matches("tun[0-9]{1,9}") || !table.matches("ssh2socks_[a-f0-9]{12}"))
            throw new IllegalArgumentException("Invalid server resource identifier");
        if (!wan.isEmpty() && !wan.matches("[a-zA-Z0-9_.:-]{1,15}"))
            throw new IllegalArgumentException("Invalid egress interface");
        if (mtu < 1280 || mtu > 32768) throw new IllegalArgumentException("Invalid VPN MTU");
        for (String address : ipv6)
            if (!address.matches("[a-fA-F0-9:]+")) throw new IllegalArgumentException("Invalid IPv6 address");
        StringBuilder script = new StringBuilder();
        script.append("set -eu\n")
                .append("IF=").append(shellQuote(interfaceName)).append("\n")
                .append("TABLE=").append(shellQuote(table)).append("\n")
                .append("MTU=").append(mtu).append("\n")
                .append("command -v ip >/dev/null 2>&1 || { echo 'missing ip command'; exit 20; }\n")
                .append("command -v nft >/dev/null 2>&1 || { echo 'missing nft command'; exit 21; }\n")
                .append("ip link show dev \"$IF\" >/dev/null 2>&1 || { echo 'sshd did not create requested TUN interface'; exit 22; }\n");
        script.append("nft list table inet \"$TABLE\" >/dev/null 2>&1 && { echo 'server resource collision'; exit 24; }\n")
                .append("OWN_TABLE=0\nOLD4=1\nOLD6=1\ncleanup(){\n")
                .append("  if [ \"$OWN_TABLE\" = 1 ]; then nft delete table inet \"$TABLE\" >/dev/null 2>&1 || true; fi\n");
        if (profile.vpnIpv4) {
            script.append("  ip address del ").append(VPN_IPV4_SERVER).append(" peer ").append(VPN_IPV4_CLIENT)
                    .append(" dev \"$IF\" >/dev/null 2>&1 || true\n")
                    .append("  if [ \"$OLD4\" = 0 ]; then printf '0\\n' > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true; fi\n");
        }
        if (profile.vpnIpv6) {
            script.append("  ip -6 route del ").append(ipv6[1]).append("/128 dev \"$IF\" >/dev/null 2>&1 || true\n")
                    .append("  ip -6 address del ").append(ipv6[0]).append("/127 peer ").append(ipv6[1])
                    .append(" dev \"$IF\" >/dev/null 2>&1 || true\n")
                    .append("  if [ \"$OLD6\" = 0 ]; then printf '0\\n' > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true; fi\n");
        }
        script.append("}\ntrap cleanup EXIT\ntrap 'exit 0' HUP TERM\n");
        if (profile.vpnIpv4) {
            if (wan.isEmpty()) {
                script.append("WAN=$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}')\n")
                        .append("[ -n \"$WAN\" ] || { echo 'no IPv4 egress interface'; exit 23; }\n");
            } else {
                script.append("WAN=").append(shellQuote(wan)).append("\n");
            }
            script.append("OLD4=$(cat /proc/sys/net/ipv4/ip_forward)\n")
                    .append("if [ \"$OLD4\" != 1 ]; then printf '1\\n' > /proc/sys/net/ipv4/ip_forward; fi\n")
                    .append("ip address replace ").append(VPN_IPV4_SERVER).append(" peer ").append(VPN_IPV4_CLIENT)
                    .append(" dev \"$IF\"\n");
        }
        if (profile.vpnIpv6) {
            script.append("OLD6=$(cat /proc/sys/net/ipv6/conf/all/forwarding)\n")
                    .append("if [ \"$OLD6\" != 1 ]; then printf '1\\n' > /proc/sys/net/ipv6/conf/all/forwarding; fi\n")
                    .append("ip -6 address replace ").append(ipv6[0]).append("/127 peer ").append(ipv6[1])
                    .append(" dev \"$IF\"\n")
                    .append("ip -6 route replace ").append(ipv6[1]).append("/128 dev \"$IF\"\n");
        }
        script.append("ip link set dev \"$IF\" mtu \"$MTU\" up\n");
        if (profile.vpnIpv4) {
            script.append("nft -f - <<EOF\n")
                    .append("add table inet $TABLE\n")
                    .append("add chain inet $TABLE forward { type filter hook forward priority filter; policy accept; }\n")
                    .append("add rule inet $TABLE forward iifname \"$IF\" oifname \"$WAN\" accept\n")
                    .append("add rule inet $TABLE forward iifname \"$WAN\" oifname \"$IF\" ct state established,related accept\n")
                    .append("add chain inet $TABLE postrouting { type nat hook postrouting priority srcnat; policy accept; }\n")
                    .append("add rule inet $TABLE postrouting oifname \"$WAN\" ip saddr ").append(VPN_IPV4_CLIENT)
                    .append(" masquerade\n")
                    .append("EOF\nOWN_TABLE=1\n");
        } else {
            script.append("nft add table inet \"$TABLE\"\nOWN_TABLE=1\n");
        }
        if (profile.vpnIpv6) {
            script.append("nft -f - <<EOF\n")
                    .append("add chain inet $TABLE forward6 { type filter hook forward priority filter; policy accept; }\n")
                    .append("add rule inet $TABLE forward6 iifname \"$IF\" accept\n")
                    .append("add rule inet $TABLE forward6 oifname \"$IF\" ct state established,related accept\n")
                    .append("EOF\n");
        }
        script.append("printf 'SSH2SOCKS_TUN_READY\\n'\nwhile :; do sleep 30; done\n");
        return script.toString();
    }


    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }
}
