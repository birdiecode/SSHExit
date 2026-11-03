package com.jcraft.jsch;

import java.io.*;
import java.nio.charset.StandardCharsets;

/** In-process channel fixture; does not simulate SSH cryptography or server setup. */
public final class GreetingTestSession extends Session {
    public GreetingTestSession() throws JSchException { super(new JSch(), "test", "127.0.0.1", 22); }
    @Override public boolean isConnected() { return true; }
    @Override public Channel openChannel(String type) throws JSchException {
        if (!"direct-tcpip".equals(type)) throw new JSchException("Unexpected channel");
        try { return new GreetingChannel(); }
        catch (IOException e) { throw new JSchException("Fixture pipe failure", e); }
    }
    private static final class GreetingChannel extends ChannelDirectTCPIP {
        final PipedInputStream received = new PipedInputStream(65536);
        final PipedOutputStream remote = new PipedOutputStream(received);
        boolean prepared;
        GreetingChannel() throws IOException { }
        @Override public InputStream getInputStream() { prepared = true; return received; }
        @Override public OutputStream getOutputStream() { return remote; }
        @Override public void connect(int timeout) throws JSchException {
            if (!prepared) throw new JSchException("Receive pipe not installed before channel open");
            try { remote.write("SERVER-HELLO".getBytes(StandardCharsets.US_ASCII)); remote.flush(); }
            catch (IOException e) { throw new JSchException("Greeting failed", e); }
        }
        @Override public void disconnect() {
            try { remote.close(); } catch (IOException ignored) { }
            try { received.close(); } catch (IOException ignored) { }
        }
    }
}
