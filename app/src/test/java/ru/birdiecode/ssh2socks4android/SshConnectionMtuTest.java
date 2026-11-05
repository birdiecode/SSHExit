package ru.birdiecode.ssh2socks4android;

import android.content.Context;
import android.net.VpnService;
import java.lang.reflect.*;
import org.junit.Test;
import org.mockito.MockedStatic;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class SshConnectionMtuTest {
    private void check(int mtu, boolean ipv6, int retainedMtu, boolean accepted) throws Exception {
        Profile profile = new Profile();
        profile.id = "mtu"; profile.connectionMode = "VPN"; profile.vpnMtu = mtu; profile.vpnIpv6 = ipv6;
        SshConnection.Host host = mock(SshConnection.Host.class);
        when(host.isCurrent(any())).thenReturn(true);
        try (MockedStatic<ProfileStore> store = mockStatic(ProfileStore.class)) {
            store.when(() -> ProfileStore.get(any(Context.class), eq(profile.id))).thenReturn(profile);
            SshConnection connection = new SshConnection(mock(VpnService.class), host, profile.id);
            try {
                VpnPacketBridge bridge = mock(VpnPacketBridge.class);
                when(bridge.mtu()).thenReturn(retainedMtu); when(bridge.failure()).thenReturn("");
                Field field = SshConnection.class.getDeclaredField("vpnBridge");
                field.setAccessible(true); field.set(connection, bridge);
                Method establish = SshConnection.class.getDeclaredMethod("establishVpnInterface", Profile.class);
                establish.setAccessible(true);
                try {
                    establish.invoke(connection, profile);
                    assertTrue("Expected MTU rejection", accepted);
                } catch (InvocationTargetException error) {
                    if (accepted) throw error;
                    assertTrue(error.getCause() instanceof IllegalArgumentException);
                    assertTrue(error.getCause().getMessage().contains("MTU"));
                }
                // Validation happens before reserving or creating another Android TUN.
                verify(host, never()).claimVpn(any());
            } finally { connection.shutdown(); }
        }
    }
    @Test public void serviceAcceptsIpv4Mtu1000AndIpv6Mtu1280() throws Exception {
        check(1000, false, 1000, true);
        check(1280, true, 1280, true);
    }
    @Test public void serviceRejectsInvalidSavedValuesBeforeTunCreation() throws Exception {
        check(1000, true, 1000, false);
        check(0, false, 0, false);
        check(9001, false, 9001, false);
    }
    @Test public void changingMtuRequiresExplicitReconnectInsteadOfMismatchedBuffers() throws Exception {
        check(1500, false, 1400, false);
    }
}
