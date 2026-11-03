package ru.birdiecode.ssh2socks4android;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Dispatches Android TUN packets to exactly one SSH TUN according to the route table. */
public final class VpnPacketRouter {
    public interface PacketWriter {
        void writePacket(byte[] packet) throws IOException;
    }

    public enum UnmatchedPolicy { DROP }

    private final VpnRouteTable routes = new VpnRouteTable();
    private final Map<String, PacketWriter> writers = new ConcurrentHashMap<>();
    private final UnmatchedPolicy unmatchedPolicy;

    public VpnPacketRouter() {
        this(UnmatchedPolicy.DROP);
    }

    public VpnPacketRouter(UnmatchedPolicy unmatchedPolicy) {
        if (unmatchedPolicy == null) throw new IllegalArgumentException("Unmatched packet policy is required");
        this.unmatchedPolicy = unmatchedPolicy;
    }

    public synchronized void attach(String connectionId, int priority, List<String> prefixes, PacketWriter writer) {
        if (writer == null) throw new IllegalArgumentException("Packet writer is required");
        routes.replaceConnectionRoutes(connectionId, priority, prefixes);
        writers.put(connectionId, writer);
    }

    public synchronized void detach(String connectionId) {
        writers.remove(connectionId);
        routes.removeConnection(connectionId);
    }

    /**
     * Routes a single raw IP packet. Returns true if a configured SSH TUN received
     * the packet; unmatched traffic follows the explicit DROP policy.
     */
    public boolean route(byte[] packet) throws IOException {
        String connectionId = routes.selectConnection(packet);
        if (connectionId == null) return unmatchedPolicy != UnmatchedPolicy.DROP;
        PacketWriter writer = writers.get(connectionId);
        if (writer == null) return false;
        writer.writePacket(packet.clone());
        return true;
    }

    public List<VpnRouteTable.Route> routes() {
        return routes.routes();
    }

    /** Adapter used by one SSH channel; each packet gets OpenSSH's uint32 frame. */
    public static PacketWriter framedWriter(OutputStream channelOutput) {
        if (channelOutput == null) throw new IllegalArgumentException("SSH channel output is required");
        DataOutputStream framed = new DataOutputStream(channelOutput);
        return packet -> {
            if (packet == null || packet.length == 0 || packet.length > 65535) {
                throw new IOException("Invalid IP packet length");
            }
            synchronized (framed) {
                int version = (packet[0] >>> 4) & 15;
                if (version != 4 && version != 6) throw new IOException("Unsupported IP version");
                framed.writeInt(packet.length + 4);
                framed.writeInt(version == 4 ? 2 : 24);
                framed.write(packet);
                framed.flush();
            }
        };
    }
}
