package ru.birdiecode.ssh2socks4android;

import org.junit.Test;
import static org.junit.Assert.*;
import static ru.birdiecode.ssh2socks4android.ConnectionStateMachine.State.*;

public class ConnectionStateMachineTest {
    @Test public void disconnectDoesNotAffectOtherConnection() {
        ConnectionStateMachine a = connected(), b = connected();
        a.disconnect();
        assertEquals(DISCONNECTED, a.get());
        assertEquals(CONNECTED, b.get());
    }
    @Test public void trustRoundTripThenVpnSetup() {
        ConnectionStateMachine a = new ConnectionStateMachine();
        a.transition(CONNECTING); a.transition(AUTHENTICATING); a.transition(NEEDS_TRUST);
        a.transition(CONNECTING); a.transition(AUTHENTICATING); a.transition(PREPARING_TUN); a.transition(NEEDS_SERVER_CONFIG);
        a.transition(CONFIGURING_SERVER); a.transition(CONNECTED);
        assertEquals(CONNECTED, a.get());
    }
    @Test public void reconnectAndManualCancel() {
        ConnectionStateMachine a = connected();
        a.transition(RECONNECTING); a.transition(CONNECTING); a.transition(AUTHENTICATING);
        a.transition(CONNECTED); a.transition(RECONNECTING); a.disconnect();
        assertEquals(DISCONNECTED, a.get());
    }
    @Test public void cannotDeclareConnectedBeforeAuthentication() {
        ConnectionStateMachine a = new ConnectionStateMachine();
        a.transition(CONNECTING);
        try { a.transition(CONNECTED); fail("Skipped authentication"); }
        catch (IllegalStateException expected) { assertEquals(CONNECTING, a.get()); }
    }
    @Test public void cancellationWorksDuringEverySetupPhase() {
        ConnectionStateMachine.State[][] paths = {
            {CONNECTING},
            {CONNECTING, AUTHENTICATING},
            {CONNECTING, AUTHENTICATING, NEEDS_PASSWORD},
            {CONNECTING, AUTHENTICATING, NEEDS_TRUST},
            {CONNECTING, AUTHENTICATING, PREPARING_TUN, NEEDS_SERVER_CONFIG},
            {CONNECTING, AUTHENTICATING, PREPARING_TUN},
            {CONNECTING, AUTHENTICATING, PREPARING_TUN, CONFIGURING_SERVER}
        };
        for (ConnectionStateMachine.State[] path : paths) {
            ConnectionStateMachine machine = new ConnectionStateMachine();
            for (ConnectionStateMachine.State state : path) machine.transition(state);
            machine.disconnect();
            machine.disconnect();
            assertEquals(DISCONNECTED, machine.get());
        }
    }

    @Test public void transportFailureDuringReconnectCanRetryAgain() {
        ConnectionStateMachine machine = connected();
        machine.transition(RECONNECTING);
        machine.transition(CONNECTING);
        machine.transition(AUTHENTICATING);
        machine.transition(RECONNECTING);
        assertEquals(RECONNECTING, machine.get());
    }

    @Test public void serverConfirmationCannotSkipTunPreparation() {
        ConnectionStateMachine machine = new ConnectionStateMachine();
        machine.transition(CONNECTING); machine.transition(AUTHENTICATING);
        machine.transition(PREPARING_TUN);
        machine.transition(NEEDS_SERVER_CONFIG);
        try { machine.transition(CONNECTED); fail("Skipped confirmed server setup"); }
        catch (IllegalStateException expected) { assertEquals(NEEDS_SERVER_CONFIG, machine.get()); }
        machine.transition(CONFIGURING_SERVER);
        machine.transition(CONNECTED);
        assertEquals(CONNECTED, machine.get());
    }


    @Test public void cannotAskForServerConfigurationBeforeTunPreparation() {
        ConnectionStateMachine machine = new ConnectionStateMachine();
        machine.transition(CONNECTING); machine.transition(AUTHENTICATING);
        try { machine.transition(NEEDS_SERVER_CONFIG); fail("Asked before opening TUN"); }
        catch (IllegalStateException expected) { assertEquals(AUTHENTICATING, machine.get()); }
        machine.transition(PREPARING_TUN);
        machine.transition(NEEDS_SERVER_CONFIG);
        machine.transition(CONFIGURING_SERVER);
        machine.transition(CONNECTED);
        assertEquals(CONNECTED, machine.get());
    }

    private ConnectionStateMachine connected() {
        ConnectionStateMachine a = new ConnectionStateMachine();
        a.transition(CONNECTING); a.transition(AUTHENTICATING); a.transition(CONNECTED);
        return a;
    }
}
