package ru.birdiecode.ssh2socks4android;

import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import com.jcraft.jsch.Session;
import java.lang.reflect.*;
import java.net.SocketTimeoutException;
import java.util.concurrent.ScheduledFuture;
import org.junit.Test;
import org.mockito.MockedStatic;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;
import static ru.birdiecode.ssh2socks4android.ConnectionFailurePolicy.Kind.*;

public class SshConnectionRetryTest {
    private final String id = "profile";
    private final Profile profile = new Profile();
    private SshConnection connection;
    private MockedStatic<ProfileStore> store;

    private void open(boolean autoReconnect) throws Exception {
        profile.id = id; profile.connectionMode = "VPN"; profile.vpnAutoReconnect = autoReconnect;
        store = mockStatic(ProfileStore.class);
        store.when(() -> ProfileStore.get(any(Context.class), eq(id))).thenReturn(profile);
        VpnService service = mock(VpnService.class);
        SshConnection.Host host = mock(SshConnection.Host.class);
        when(host.isCurrent(any())).thenReturn(true);
        doAnswer(call -> { ((Runnable) call.getArgument(0)).run(); return null; }).when(host).cleanup(any());
        connection = new SshConnection(service, host, id);
    }
    private void close() {
        if (connection != null) connection.shutdown();
        if (store != null) store.close();
    }
    private void field(String name, Object value) throws Exception {
        Field field = SshConnection.class.getDeclaredField(name);
        field.setAccessible(true); field.set(connection, value);
    }
    private Object field(String name) throws Exception {
        Field field = SshConnection.class.getDeclaredField(name);
        field.setAccessible(true); return field.get(connection);
    }
    private void stage(ConnectionStateMachine.State next) throws Exception {
        ConnectionStateMachine machine = (ConnectionStateMachine) field("lifecycle");
        if (next != ConnectionStateMachine.State.CONNECTING)
            machine.transition(ConnectionStateMachine.State.AUTHENTICATING);
        if (next == ConnectionStateMachine.State.NEEDS_SERVER_CONFIG) {
            machine.transition(ConnectionStateMachine.State.PREPARING_TUN);
            machine.transition(next);
        }
        if (next == ConnectionStateMachine.State.PREPARING_TUN
                || next == ConnectionStateMachine.State.CONFIGURING_SERVER) {
            machine.transition(ConnectionStateMachine.State.PREPARING_TUN);
            if (next == ConnectionStateMachine.State.CONFIGURING_SERVER) machine.transition(next);
        }
        connection.state = next.name();
    }
    private void failure(Exception error) throws Exception {
        Method method = SshConnection.class.getDeclaredMethod("handleConnectFailure", Exception.class, String.class);
        method.setAccessible(true); method.invoke(connection, error, "test failure");
    }

    @Test public void initialTransientFailureCanRetryFromEveryConnectionStage() throws Exception {
        for (ConnectionStateMachine.State stage : new ConnectionStateMachine.State[]{
                ConnectionStateMachine.State.CONNECTING, ConnectionStateMachine.State.AUTHENTICATING,
                ConnectionStateMachine.State.NEEDS_SERVER_CONFIG, ConnectionStateMachine.State.PREPARING_TUN,
                ConnectionStateMachine.State.CONFIGURING_SERVER}) {
            try {
                open(true); stage(stage);
                failure(new SocketTimeoutException());
                assertEquals("RECONNECTING", connection.state);
                assertNotNull(field("retry"));
            } finally { close(); }
            connection = null; store = null;
        }
    }

    @Test public void applyingPlanAfterSessionLossRetriesEvenBeforeFirstVpnSuccess() throws Exception {
        try {
            open(true); stage(ConnectionStateMachine.State.NEEDS_SERVER_CONFIG);
            field("pendingServerRequest", "request");
            Session session = mock(Session.class); when(session.isConnected()).thenReturn(false);
            field("activeSession", session);
            Intent intent = mock(Intent.class); when(intent.getStringExtra("server_request")).thenReturn("request");
            connection.applyServerPlan(intent);
            assertEquals("RECONNECTING", connection.state);
            assertNotNull(field("retry"));
        } finally { close(); }
    }

    @Test public void waitingServerConfirmationDetectsSessionLossWithoutUserClick() throws Exception {
        try {
            open(true); stage(ConnectionStateMachine.State.NEEDS_SERVER_CONFIG);
            Method health = SshConnection.class.getDeclaredMethod("checkHealth"); health.setAccessible(true);
            health.invoke(connection);
            assertEquals("RECONNECTING", connection.state);
        } finally { close(); }
    }

    @Test public void disabledReconnectAndPermanentErrorsDoNotScheduleRetries() throws Exception {
        try {
            open(false); stage(ConnectionStateMachine.State.CONFIGURING_SERVER);
            failure(new SocketTimeoutException());
            assertEquals("ERROR", connection.state); assertNull(field("retry"));
        } finally { close(); }
        connection = null; store = null;
        for (ConnectionFailurePolicy.Kind kind : new ConnectionFailurePolicy.Kind[]{CONFIGURATION, AUTHENTICATION, TRUST}) {
            try {
                open(true); stage(ConnectionStateMachine.State.CONFIGURING_SERVER);
                failure(new ConnectionFailurePolicy.Failure(kind, "stop"));
                assertEquals("ERROR", connection.state); assertNull(field("retry"));
            } finally { close(); }
            connection = null; store = null;
        }
    }

    @Test public void cancellationAndManualShutdownStopScheduledRecovery() throws Exception {
        try {
            open(true); stage(ConnectionStateMachine.State.CONFIGURING_SERVER);
            failure(new SocketTimeoutException());
            ScheduledFuture<?> retry = (ScheduledFuture<?>) field("retry");
            connection.shutdown();
            assertTrue(retry.isCancelled()); assertEquals("IDLE", connection.state);
        } finally { close(); }
        connection = null; store = null;
        try {
            open(true); stage(ConnectionStateMachine.State.CONFIGURING_SERVER);
            failure(new ConnectionFailurePolicy.Failure(CANCELLED, "cancel"));
            assertEquals("IDLE", connection.state); assertNull(field("retry"));
        } finally { close(); }
    }
}
