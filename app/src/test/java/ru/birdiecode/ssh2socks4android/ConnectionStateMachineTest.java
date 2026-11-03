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
        a.transition(CONNECTING); a.transition(AUTHENTICATING); a.transition(PREPARING_TUN);
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
    private ConnectionStateMachine connected() {
        ConnectionStateMachine a = new ConnectionStateMachine();
        a.transition(CONNECTING); a.transition(AUTHENTICATING); a.transition(CONNECTED);
        return a;
    }
}
