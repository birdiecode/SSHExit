package ru.birdiecode.ssh2socks4android;

import android.content.Context;
import android.content.Intent;
import com.jcraft.jsch.*;
import java.io.*;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/** Exercises the real connection flow with only SSH and Android I/O boundaries mocked. */
public class SshConnectionPlanOrderTest {
    private void field(SshConnection connection, String name, Object value) throws Exception {
        Field field = SshConnection.class.getDeclaredField(name);
        field.setAccessible(true); field.set(connection, value);
    }
    private Object field(SshConnection connection, String name) throws Exception {
        Field field = SshConnection.class.getDeclaredField(name);
        field.setAccessible(true); return field.get(connection);
    }

    private void run(boolean rejectTun, boolean skipConfirmation, boolean confirm) throws Exception {
        Profile profile = new Profile();
        profile.id = "profile"; profile.name = "VPN"; profile.host = "server"; profile.username = "user";
        profile.connectionMode = "VPN"; profile.vpnExternalInterface = "eth0";
        profile.serverSkipConfirmation = skipConfirmation;
        Session ssh = mock(Session.class); when(ssh.isConnected()).thenReturn(true);
        ChannelExec monitor = mock(ChannelExec.class);
        when(monitor.getInputStream()).thenReturn(new ByteArrayInputStream("SSH2SOCKS_TUN_READY\n".getBytes("UTF-8")));
        when(monitor.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        when(ssh.openChannel("exec")).thenReturn(monitor);
        VpnPacketBridge bridge = mock(VpnPacketBridge.class);
        VpnPacketBridge.Endpoint packets = mock(VpnPacketBridge.Endpoint.class);
        when(bridge.failure()).thenReturn(""); when(bridge.addressSlot()).thenReturn(1000001);
        when(bridge.prepareEndpoint()).thenReturn(packets);
        when(packets.outgoing()).thenReturn(new ByteArrayInputStream(new byte[0]));
        when(packets.incoming()).thenReturn(new ByteArrayOutputStream());
        SshConnection.Host host = mock(SshConnection.Host.class);
        when(host.isCurrent(any())).thenReturn(true);
        doAnswer(call -> { ((Runnable) call.getArgument(0)).run(); return null; }).when(host).cleanup(any());
        AtomicBoolean opened = new AtomicBoolean();
        try (MockedStatic<ProfileStore> store = mockStatic(ProfileStore.class);
             MockedStatic<SshKeyStore> keys = mockStatic(SshKeyStore.class);
             MockedConstruction<JSch> clients = mockConstruction(JSch.class, (client, context) -> {
                 when(client.getSession(anyString(), anyString(), anyInt())).thenReturn(ssh);
             });
             MockedConstruction<OpenSshTunChannel> tunnels = mockConstruction(OpenSshTunChannel.class, (tun, context) -> {
                 when(tun.isConnected()).thenReturn(true);
                 when(tun.getExitStatus()).thenReturn(rejectTun ? 1 : -1);
                 doAnswer(call -> {
                     if (rejectTun) throw new JSchException("channel is not opened.");
                     opened.set(true); return null;
                 }).when(tun).openOn(ssh, 20_000);
             })) {
            store.when(() -> ProfileStore.get(any(Context.class), eq(profile.id))).thenReturn(profile);
            keys.when(() -> SshKeyStore.all(any(Context.class))).thenReturn(java.util.Collections.emptyList());
            store.when(() -> ProfileStore.setStatus(any(Context.class), eq(profile.id),
                    eq("NEEDS_SERVER_CONFIG"), anyString())).thenAnswer(call -> {
                assertTrue("Prompt must follow successful TUN open", opened.get());
                verify(packets, never()).enable();
                verify(ssh, never()).openChannel("exec"); // No server configuration before consent.
                return null;
            });
            SshConnection connection = new SshConnection(mock(android.net.VpnService.class), host, profile.id);
            try {
                field(connection, "vpnBridge", bridge);
                connection.connect(profile.id);
                assertEquals(1, tunnels.constructed().size());
                OpenSshTunChannel tun = tunnels.constructed().get(0);
                verify(tun, times(1)).openOn(ssh, 20_000);
                if (rejectTun) {
                    assertEquals("ERROR", connection.state);
                    store.verify(() -> ProfileStore.setStatus(any(Context.class), eq(profile.id),
                            eq("NEEDS_SERVER_CONFIG"), anyString()), never());
                    verify(packets, never()).enable();
                    verify(ssh, never()).openChannel("exec");
                } else if (skipConfirmation) {
                    assertEquals("CONNECTED", connection.state);
                    store.verify(() -> ProfileStore.setStatus(any(Context.class), eq(profile.id),
                            eq("NEEDS_SERVER_CONFIG"), anyString()), never());
                    verify(packets).enable();
                } else {
                    assertEquals("NEEDS_SERVER_CONFIG", connection.state);
                    verify(packets, never()).enable();
                    verify(ssh, never()).openChannel("exec");
                    if (confirm) {
                        Intent intent = mock(Intent.class);
                        when(intent.getStringExtra("server_request")).thenReturn((String) field(connection, "pendingServerRequest"));
                        when(intent.getStringExtra("server_wan")).thenReturn("eth0");
                        connection.applyServerPlan(intent);
                        assertEquals("CONNECTED", connection.state);
                        verify(packets, times(1)).enable();
                        verify(tun, times(1)).openOn(ssh, 20_000);
                        connection.applyServerPlan(intent); // Duplicate submission is ignored.
                        verify(packets, times(1)).enable();
                        verify(ssh, times(1)).openChannel("exec");
                    }
                }
            } finally { connection.shutdown(); }
            if (!rejectTun && !skipConfirmation && !confirm) {
                verify(ssh, never()).openChannel("exec");
                verify(packets, never()).enable();
                verify(tunnels.constructed().get(0)).disconnect();
            }
        }
    }

    @Test public void openChannelBeforePromptAndReuseItAfterConfirmation() throws Exception { run(false, false, true); }
    @Test public void rejectedTunNeverShowsServerSettings() throws Exception { run(true, false, false); }
    @Test public void cancellationClosesPreparedTunWithoutApplyingServerPlan() throws Exception { run(false, false, false); }
    @Test public void skippedConfirmationStillOpensTunBeforeServerSetup() throws Exception { run(false, true, false); }
}
