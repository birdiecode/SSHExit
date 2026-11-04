package ru.birdiecode.ssh2socks4android;

import org.junit.Test;
import com.jcraft.jsch.JSchException;
import java.io.*;
import java.net.*;
import static org.junit.Assert.*;
import static ru.birdiecode.ssh2socks4android.ConnectionFailurePolicy.Kind.*;

public class ConnectionFailurePolicyTest {
    @Test public void wrappedNetworkFailuresRetryWithoutDependingOnVpnHistory() {
        for (Exception failure : new Exception[]{new SocketTimeoutException(), new ConnectException(),
                new NoRouteToHostException(), new UnknownHostException(), new EOFException(),
                new SocketException("reset")}) {
            assertEquals(TEMPORARY_NETWORK, ConnectionFailurePolicy.classify(new Exception("node", failure)));
        }
    }
    @Test public void authenticationAndTrustNeverBecomeNetworkRetries() {
        assertEquals(AUTHENTICATION, ConnectionFailurePolicy.classify(new Exception("node",
                new JSchException("Auth fail for methods 'publickey,password'"))));
        assertEquals(TRUST, ConnectionFailurePolicy.classify(new JSchException("HostKey has been changed")));
        assertEquals(TRUST, ConnectionFailurePolicy.classify(new ConnectionFailurePolicy.Failure(
                TRUST, "pin mismatch", new SocketException())));
    }
    @Test public void configurationAndUnknownErrorsStop() {
        for (Exception failure : new Exception[]{new BindException("occupied"),
                new IllegalArgumentException("bad MTU"), new FileNotFoundException(),
                new ProtocolException(), new IllegalStateException("storage"),
                new JSchException("Algorithm negotiation fail"), new IOException("unknown local error")}) {
            assertEquals(CONFIGURATION, ConnectionFailurePolicy.classify(failure));
        }
    }
    @Test public void cancellationIsDistinctFromSocketTimeout() {
        assertEquals(CANCELLED, ConnectionFailurePolicy.classify(new InterruptedException()));
        assertEquals(CANCELLED, ConnectionFailurePolicy.classify(new InterruptedIOException()));
        assertEquals(TEMPORARY_NETWORK, ConnectionFailurePolicy.classify(new SocketTimeoutException()));
        assertEquals(CANCELLED, ConnectionFailurePolicy.transportIo(new InterruptedIOException(), "io").kind);
    }
    @Test public void flattenedJschNetworkErrorsAreRecognized() {
        for (String message : new String[]{"Session.connect: java.net.SocketTimeoutException",
                "session is down", "connection is closed by foreign host", "connection refused"}) {
            assertEquals(TEMPORARY_NETWORK, ConnectionFailurePolicy.classify(new JSchException(message)));
        }
    }
    @Test public void noRetryAfterManualStopDisabledReconnectOrProfileReplacement() {
        assertTrue(ConnectionFailurePolicy.shouldRetry(TEMPORARY_NETWORK, true, false, true));
        assertFalse(ConnectionFailurePolicy.shouldRetry(TEMPORARY_NETWORK, false, false, true));
        assertFalse(ConnectionFailurePolicy.shouldRetry(TEMPORARY_NETWORK, true, true, true));
        assertFalse(ConnectionFailurePolicy.shouldRetry(TEMPORARY_NETWORK, true, false, false));
        for (ConnectionFailurePolicy.Kind kind : new ConnectionFailurePolicy.Kind[]{
                CONFIGURATION, AUTHENTICATION, TRUST, CANCELLED})
            assertFalse(ConnectionFailurePolicy.shouldRetry(kind, true, false, true));
    }
    @Test public void serverStatusSeparatesMissingReplyFromDeterministicRejection() {
        assertEquals(TEMPORARY_NETWORK, ConnectionFailurePolicy.serverExit(-1, false));
        for (int status : new int[]{0,1,20,21,22,23,24,25,26,27,28,29,30,31,32,126,127})
            assertEquals(CONFIGURATION, ConnectionFailurePolicy.serverExit(status, false));
        assertEquals(TEMPORARY_NETWORK, ConnectionFailurePolicy.serverExit(29, true));
        assertEquals(CONFIGURATION, ConnectionFailurePolicy.serverExit(25, true));
    }
    @Test public void channelOpenTimeoutAndResourceShortageDifferFromPermitTunnelRejection() {
        JSchException error = new JSchException("channel is not opened.");
        assertEquals(TEMPORARY_NETWORK, ConnectionFailurePolicy.channelOpen(error, -1, true).kind);
        assertEquals(TEMPORARY_NETWORK, ConnectionFailurePolicy.channelOpen(error, 4, true).kind);
        assertEquals(TEMPORARY_NETWORK, ConnectionFailurePolicy.channelOpen(error, 2, true).kind);
        assertEquals(CONFIGURATION, ConnectionFailurePolicy.channelOpen(error, 1, true).kind);
        assertEquals(CONFIGURATION, ConnectionFailurePolicy.channelOpen(error, 1, false).kind);
        assertEquals(CONFIGURATION, ConnectionFailurePolicy.channelOpen(error, 3, true).kind);
    }
}
