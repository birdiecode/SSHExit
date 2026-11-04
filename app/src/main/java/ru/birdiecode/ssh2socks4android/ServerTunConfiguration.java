package ru.birdiecode.ssh2socks4android;

/** Owns server shell generation; never invokes privilege escalation. */
final class ServerTunConfiguration {
    static String build(Profile profile, String interfaceName, String table,
                                        int mtu, String[] ipv6) {
        return build(profile, interfaceName, table, mtu, ipv6, TunAddressPlan.unit(interfaceName));
    }

    static String build(Profile profile, String interfaceName, String table, int mtu, String[] ipv6, int addressSlot) {
        String[] ipv4 = TunAddressPlan.ipv4(addressSlot);
        String server4 = ipv4[0], client4 = ipv4[1];
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
                .append("command -v timeout >/dev/null 2>&1 || { echo 'missing timeout command'; exit 27; }\n")
                .append("ip link show dev \"$IF\" >/dev/null 2>&1 || { echo 'sshd did not create requested TUN interface'; exit 22; }\n");
        script.append("[ -z \"$(ip -o addr show dev \"$IF\" scope global)\" ] || { echo 'TUN interface already has addresses; refusing to modify it'; exit 28; }\n");
        script.append("nft list table inet \"$TABLE\" >/dev/null 2>&1 && { echo 'server resource collision'; exit 24; }\n")
                .append("OWN_TABLE=0\nADDR4=0\nADDR6=0\nROUTE4=0\nROUTE6=0\ncleanup(){\n  CLEANUP_OK=1\n")
                .append("  if [ \"$OWN_TABLE\" = 1 ]; then nft delete table inet \"$TABLE\" >/dev/null 2>&1 || CLEANUP_OK=0; fi\n");
        if (profile.vpnIpv4) {
            script.append("  if [ \"$ROUTE4\" = 1 ]; then ip -4 route del ").append(client4)
                    .append("/32 dev \"$IF\" proto static >/dev/null 2>&1 || { [ -z \"$(ip -4 route show exact ")
                    .append(client4).append("/32 dev \"$IF\" proto static 2>/dev/null)\" ] || { echo SSHEXIT_CLEANUP_STEP_FAILED:route4; CLEANUP_OK=0; }; }; fi\n")
                    .append("  if [ \"$ADDR4\" = 1 ]; then ip address del ").append(server4).append("/32 peer ").append(client4)
                    .append("/32 dev \"$IF\" >/dev/null 2>&1 || { [ -z \"$(ip -4 -o addr show dev \"$IF\" to ")
                    .append(server4).append("/32 2>/dev/null)\" ] || { echo SSHEXIT_CLEANUP_STEP_FAILED:address4; CLEANUP_OK=0; }; }; fi\n");
        }
        if (profile.vpnIpv6) {
            script.append("  if [ \"$ROUTE6\" = 1 ]; then ip -6 route del ").append(ipv6[1])
                    .append("/128 dev \"$IF\" proto static >/dev/null 2>&1 || { [ -z \"$(ip -6 route show exact ")
                    .append(ipv6[1]).append("/128 dev \"$IF\" proto static 2>/dev/null)\" ] || { echo SSHEXIT_CLEANUP_STEP_FAILED:route6; CLEANUP_OK=0; }; }; fi\n")
                    .append("  if [ \"$ADDR6\" = 1 ]; then ip -6 address del ").append(ipv6[0]).append("/128 peer ").append(ipv6[1])
                    .append("/128 dev \"$IF\" >/dev/null 2>&1 || { [ -z \"$(ip -6 -o addr show dev \"$IF\" to ")
                    .append(ipv6[0]).append("/128 2>/dev/null)\" ] || { echo SSHEXIT_CLEANUP_STEP_FAILED:address6; CLEANUP_OK=0; }; }; fi\n");
        }
        script.append("  if [ \"$CLEANUP_OK\" = 1 ]; then echo SSHEXIT_CLEANUP_DONE; else echo SSHEXIT_CLEANUP_FAILED; fi\n}\ntrap cleanup EXIT\ntrap 'exit 0' HUP TERM\n");
        script.append("ip link set dev \"$IF\" mtu \"$MTU\" up\necho SSHEXIT_APPLIED:link\n");
        if (profile.vpnIpv4) {
            script.append("[ -z \"$(ip -4 -o addr show to ").append(server4).append("/32)\" ] || { echo SSHEXIT_ADDRESS_CONFLICT; exit 31; }\n")
                    .append("if ip -4 route show match ").append(client4).append("/32 | grep -qv '^default '; then echo SSHEXIT_ADDRESS_CONFLICT; exit 29; fi\n");
            if (wan.isEmpty()) {
                script.append("WAN=$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}')\n")
                        .append("[ -n \"$WAN\" ] || { echo 'no IPv4 egress interface'; exit 23; }\n");
            } else {
                script.append("WAN=").append(shellQuote(wan)).append("\n");
            }
            script.append(profile.serverManageIpv4Forwarding ? "CURRENT4=$(cat /proc/sys/net/ipv4/ip_forward)\n" : "[ \"$(cat /proc/sys/net/ipv4/ip_forward)\" = 1 ] || { echo 'IPv4 forwarding is disabled; automatic change was not approved'; exit 25; }\n")
                    .append(profile.serverManageIpv4Forwarding ? "if [ \"$CURRENT4\" != 1 ]; then printf '1\\n' > /proc/sys/net/ipv4/ip_forward; fi\necho SSHEXIT_APPLIED:forward4\n" : "")
                    .append("ip -4 route add ").append(client4).append("/32 dev \"$IF\" proto static || { echo SSHEXIT_ADDRESS_CONFLICT; exit 29; }\nROUTE4=1\n")
                    .append("ip address add ").append(server4).append("/32 peer ").append(client4)
                    .append("/32 dev \"$IF\" noprefixroute\nADDR4=1\necho SSHEXIT_APPLIED:address4\n");
        }
        if (profile.vpnIpv6) {
            script.append("[ -z \"$(ip -6 -o addr show to ").append(ipv6[0]).append("/128)\" ] || { echo SSHEXIT_ADDRESS_CONFLICT; exit 32; }\n");
            script.append("[ -z \"$(ip -6 route show exact ").append(ipv6[1]).append("/128)\" ] || { echo SSHEXIT_ADDRESS_CONFLICT; exit 30; }\n");
            script.append(profile.serverManageIpv6Forwarding ? "CURRENT6=$(cat /proc/sys/net/ipv6/conf/all/forwarding)\n" : "[ \"$(cat /proc/sys/net/ipv6/conf/all/forwarding)\" = 1 ] || { echo 'IPv6 forwarding is disabled; automatic change was not approved'; exit 26; }\n")
                    .append(profile.serverManageIpv6Forwarding ? "if [ \"$CURRENT6\" != 1 ]; then printf '1\\n' > /proc/sys/net/ipv6/conf/all/forwarding; fi\necho SSHEXIT_APPLIED:forward6\n" : "")
                    .append("ip -6 route add ").append(ipv6[1]).append("/128 dev \"$IF\" proto static || { echo SSHEXIT_ADDRESS_CONFLICT; exit 30; }\nROUTE6=1\n")
                    .append("ip -6 address add ").append(ipv6[0]).append("/128 peer ").append(ipv6[1])
                    .append("/128 dev \"$IF\" noprefixroute\nADDR6=1\necho SSHEXIT_APPLIED:address6\n");
        }
        script.append("nft -f - <<EOF\nadd table inet $TABLE\n");
        if (profile.vpnIpv4) {
            script.append("add chain inet $TABLE forward { type filter hook forward priority filter; policy accept; }\n");
            if (profile.serverAcceptOutbound)
                script.append("add rule inet $TABLE forward iifname \"$IF\" oifname \"$WAN\" accept\n");
            if (profile.serverAcceptReturn)
                script.append("add rule inet $TABLE forward iifname \"$WAN\" oifname \"$IF\" ct state established,related accept\n");
            if (profile.serverNatIpv4) {
                script.append("add chain inet $TABLE postrouting { type nat hook postrouting priority srcnat; policy accept; }\n")
                        .append("add rule inet $TABLE postrouting oifname \"$WAN\" ip saddr ")
                        .append(client4).append(" masquerade\n");
            }
        }
        if (profile.vpnIpv6) {
            script.append("add chain inet $TABLE forward6 { type filter hook forward priority filter; policy accept; }\n");
            if (profile.serverAcceptOutbound)
                script.append("add rule inet $TABLE forward6 iifname \"$IF\" accept\n");
            if (profile.serverAcceptReturn)
                script.append("add rule inet $TABLE forward6 oifname \"$IF\" ct state established,related accept\n");
        }
        script.append("EOF\nOWN_TABLE=1\necho SSHEXIT_APPLIED:nft\n");
        script.append("# Global forwarding remains enabled for other clients. Only this connection's resources are removed.\n")
                .append("printf 'SSH2SOCKS_TUN_READY\\n'\n")
                .append("while :; do\n  COMMAND=$(timeout 60 sh -c 'IFS= read -r line && printf \"%s\" \"$line\"') || { echo SSHEXIT_LEASE_EXPIRED; break; }\n")
                .append("  case \"$COMMAND\" in alive) : ;; stop) break ;; *) break ;; esac\ndone\n");
        return script.toString();
    }


    static String preview(Profile profile, String interfaceName, String table, String[] ipv6) {
        return preview(profile, interfaceName, table, ipv6, TunAddressPlan.unit(interfaceName));
    }

    static String preview(Profile profile, String interfaceName, String table, String[] ipv6, int addressSlot) {
        return build(profile, interfaceName, table, profile.vpnMtu, ipv6, addressSlot);
    }

    static String appliedDescription(String stage, Profile profile, String interfaceName, String table, String[] ipv6) {
        return appliedDescription(stage, profile, interfaceName, table, ipv6, TunAddressPlan.unit(interfaceName));
    }

    static String appliedDescription(String stage, Profile profile, String interfaceName, String table, String[] ipv6, int addressSlot) {
        String[] ipv4 = TunAddressPlan.ipv4(addressSlot);
        String server4 = ipv4[0], client4 = ipv4[1];
        if ("forward4".equals(stage)) return "IPv4 forwarding включён; при отключении не выключается, чтобы не затронуть других клиентов";
        if ("forward6".equals(stage)) return "IPv6 forwarding включён; при отключении не выключается, чтобы не затронуть других клиентов";
        if ("address4".equals(stage)) return "ip address add " + server4 + "/32 peer " + client4 + "/32 dev " + interfaceName + "; route " + client4 + "/32";
        if ("address6".equals(stage)) return "IPv6 адрес " + ipv6[0] + ", peer " + ipv6[1] + ", маршрут /128 через " + interfaceName;
        if ("link".equals(stage)) return "ip link set dev " + interfaceName + " mtu " + profile.vpnMtu + " up";
        if ("nft".equals(stage)) {
            String script = build(profile, interfaceName, table, profile.vpnMtu, ipv6, addressSlot);
            int start = script.indexOf("add table inet $TABLE");
            int end = script.indexOf("\nEOF", start);
            return script.substring(start, end).replace("$TABLE", table).replace("$IF", interfaceName)
                    .replace("$WAN", profile.vpnExternalInterface);
        }
        return "";
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }
}
