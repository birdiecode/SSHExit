package ru.birdiecode.ssh2socks4android;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Thread-safe longest-prefix router used to dispatch Android TUN packets to SSH TUN channels. */
public final class VpnRouteTable {
    public static final class Route {
        public final String connectionId;
        public final String prefix;
        public final int priority;

        Route(String connectionId, String prefix, int priority) {
            this.connectionId = connectionId;
            this.prefix = prefix;
            this.priority = priority;
        }
    }

    private static final class Entry {
        final String connectionId;
        final byte[] network;
        final int prefixLength;
        final int priority;
        final String prefix;

        Entry(String connectionId, byte[] network, int prefixLength, int priority, String prefix) {
            this.connectionId = connectionId;
            this.network = network;
            this.prefixLength = prefixLength;
            this.priority = priority;
            this.prefix = prefix;
        }

        boolean matches(byte[] address) {
            if (address.length != network.length) return false;
            int wholeBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;
            for (int i = 0; i < wholeBytes; i++) {
                if (address[i] != network[i]) return false;
            }
            if (remainingBits == 0) return true;
            int mask = 0xff << (8 - remainingBits);
            return ((address[wholeBytes] & 0xff) & mask) == ((network[wholeBytes] & 0xff) & mask);
        }
    }

    private final List<Entry> entries = new ArrayList<>();

    /**
     * Atomically replaces all routes owned by one SSH connection. Equal prefixes
     * with equal priority are rejected so routing never depends on insertion order.
     */
    public synchronized void replaceConnectionRoutes(String connectionId, int priority, List<String> prefixes) {
        if (connectionId == null || connectionId.trim().isEmpty()) {
            throw new IllegalArgumentException("Connection ID is required");
        }
        List<Entry> candidate = new ArrayList<>();
        for (Entry current : entries) {
            if (!connectionId.equals(current.connectionId)) candidate.add(current);
        }

        Set<String> owned = new HashSet<>();
        for (String value : prefixes == null ? Collections.<String>emptyList() : prefixes) {
            Entry parsed = parse(connectionId, priority, value);
            String key = parsed.prefix + "@" + priority;
            if (!owned.add(key)) throw new IllegalArgumentException("Duplicate route: " + parsed.prefix);
            for (Entry existing : candidate) {
                if (parsed.prefixLength == existing.prefixLength
                        && parsed.priority == existing.priority
                        && Arrays.equals(parsed.network, existing.network)) {
                    throw new IllegalArgumentException("Route conflict for " + parsed.prefix
                            + " at priority " + priority);
                }
            }
            candidate.add(parsed);
        }
        entries.clear();
        entries.addAll(candidate);
    }

    public synchronized void removeConnection(String connectionId) {
        entries.removeIf(entry -> entry.connectionId.equals(connectionId));
    }

    /** Returns the owning connection ID, or null if no configured prefix matches. */
    public synchronized String selectConnection(byte[] packet) {
        byte[] destination = destinationAddress(packet);
        Entry best = null;
        for (Entry entry : entries) {
            if (!entry.matches(destination)) continue;
            if (best == null || entry.prefixLength > best.prefixLength
                    || (entry.prefixLength == best.prefixLength && entry.priority > best.priority)) {
                best = entry;
            }
        }
        return best == null ? null : best.connectionId;
    }

    public synchronized List<Route> routes() {
        ArrayList<Route> result = new ArrayList<>();
        for (Entry entry : entries) result.add(new Route(entry.connectionId, entry.prefix, entry.priority));
        result.sort(Comparator.comparing((Route route) -> route.prefix).thenComparingInt(route -> -route.priority));
        return Collections.unmodifiableList(result);
    }

    private static byte[] destinationAddress(byte[] packet) {
        if (packet == null || packet.length < 1) throw new IllegalArgumentException("Empty IP packet");
        int version = (packet[0] >>> 4) & 0x0f;
        if (version == 4) {
            if (packet.length < 20) throw new IllegalArgumentException("Truncated IPv4 packet");
            int headerLength = (packet[0] & 0x0f) * 4;
            if (headerLength < 20 || packet.length < headerLength) {
                throw new IllegalArgumentException("Invalid IPv4 header length");
            }
            return Arrays.copyOfRange(packet, 16, 20);
        }
        if (version == 6) {
            if (packet.length < 40) throw new IllegalArgumentException("Truncated IPv6 packet");
            return Arrays.copyOfRange(packet, 24, 40);
        }
        throw new IllegalArgumentException("Unsupported IP version: " + version);
    }

    private static Entry parse(String connectionId, int priority, String value) {
        if (value == null) throw new IllegalArgumentException("Route prefix is required");
        String input = value.trim();
        int slash = input.lastIndexOf('/');
        if (slash <= 0 || slash == input.length() - 1) {
            throw new IllegalArgumentException("Route must use CIDR notation: " + value);
        }
        String addressText = input.substring(0, slash);
        if (addressText.contains("%")) throw new IllegalArgumentException("IPv6 zone IDs are not valid route prefixes");
        byte[] address;
        try {
            if (addressText.indexOf(':') >= 0) {
                address = InetAddress.getByName(addressText).getAddress();
                if (address.length != 16) throw new IllegalArgumentException("Invalid IPv6 address: " + addressText);
            } else {
                address = parseIpv4(addressText);
            }
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException) throw (IllegalArgumentException) e;
            throw new IllegalArgumentException("Invalid route address: " + addressText, e);
        }
        int max = address.length * 8;
        int prefixLength;
        try {
            prefixLength = Integer.parseInt(input.substring(slash + 1));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid route prefix length: " + value, e);
        }
        if (prefixLength < 0 || prefixLength > max) {
            throw new IllegalArgumentException("Route prefix length must be between 0 and " + max);
        }
        byte[] network = address.clone();
        int fullBytes = prefixLength / 8;
        int partialBits = prefixLength % 8;
        if (partialBits != 0) network[fullBytes] &= (byte) (0xff << (8 - partialBits));
        for (int i = fullBytes + (partialBits == 0 ? 0 : 1); i < network.length; i++) network[i] = 0;
        String canonical = toAddress(network) + "/" + prefixLength;
        return new Entry(connectionId, network, prefixLength, priority, canonical);
    }

    private static byte[] parseIpv4(String value) {
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) throw new IllegalArgumentException("Invalid IPv4 address: " + value);
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            if (octets[i].isEmpty() || !octets[i].matches("[0-9]{1,3}")) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + value);
            }
            int parsed = Integer.parseInt(octets[i]);
            if (parsed > 255) throw new IllegalArgumentException("Invalid IPv4 address: " + value);
            bytes[i] = (byte) parsed;
        }
        return bytes;
    }

    private static String toAddress(byte[] bytes) {
        try {
            return InetAddress.getByAddress(bytes).getHostAddress();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
