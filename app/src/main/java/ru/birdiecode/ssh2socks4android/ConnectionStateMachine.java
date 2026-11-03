package ru.birdiecode.ssh2socks4android;

import java.util.EnumSet;

/** Explicit lifecycle; IDLE is mapped to DISCONNECTED only at the persistence boundary. */
final class ConnectionStateMachine {
    enum State {
        DISCONNECTED, CONNECTING, AUTHENTICATING, NEEDS_PASSWORD, NEEDS_TRUST,
        PREPARING_TUN, CONFIGURING_SERVER, CONNECTED, RECONNECTING, DISCONNECTING, ERROR
    }
    private State state = State.DISCONNECTED;

    synchronized State get() { return state; }

    synchronized void transition(State next) {
        if (next == state) return;
        boolean allowed;
        if (next == State.DISCONNECTING) allowed = state != State.DISCONNECTED;
        else if (next == State.ERROR) allowed = state != State.DISCONNECTED && state != State.DISCONNECTING;
        else {
            switch (state) {
                case DISCONNECTED: case ERROR: case NEEDS_PASSWORD: case NEEDS_TRUST: case RECONNECTING:
                    allowed = next == State.CONNECTING; break;
                case CONNECTING:
                    allowed = next == State.AUTHENTICATING; break;
                case AUTHENTICATING:
                    allowed = EnumSet.of(State.NEEDS_PASSWORD, State.NEEDS_TRUST,
                            State.PREPARING_TUN, State.CONNECTED).contains(next); break;
                case PREPARING_TUN:
                    allowed = next == State.CONFIGURING_SERVER; break;
                case CONFIGURING_SERVER:
                    allowed = next == State.CONNECTED; break;
                case CONNECTED:
                    allowed = next == State.RECONNECTING; break;
                case DISCONNECTING:
                    allowed = next == State.DISCONNECTED; break;
                default: allowed = false;
            }
        }
        if (!allowed) throw new IllegalStateException("Invalid connection transition: " + state + " -> " + next);
        state = next;
    }

    synchronized void disconnect() {
        if (state == State.DISCONNECTED) return;
        transition(State.DISCONNECTING);
        transition(State.DISCONNECTED);
    }
}
