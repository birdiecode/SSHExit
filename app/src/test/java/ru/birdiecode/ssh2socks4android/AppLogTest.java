package ru.birdiecode.ssh2socks4android;

import org.junit.Test;
import static org.junit.Assert.*;

public class AppLogTest {
    @Test public void verbosityFiltersWithoutLosingEarlierDebugEvents() {
        AppLog log = new AppLog(10);
        log.record(AppLog.ERROR, "test", "failed-event");
        log.record(AppLog.INFO, "test", "connected-event");
        log.record(AppLog.TRACE, "test", "trace-event");
        assertTrue(log.render(0).contains("failed-event"));
        assertFalse(log.render(0).contains("connected-event"));
        assertTrue(log.render(2).contains("connected-event"));
        assertFalse(log.render(2).contains("trace-event"));
        assertTrue(log.render(4).contains("trace-event"));
    }
    @Test public void boundedRetentionAndClearUpdateRevision() {
        AppLog log = new AppLog(2);
        log.record(2, "test", "oldest-event");
        log.record(2, "test", "middle-event");
        log.record(2, "test", "newest-event");
        String result = log.render(4);
        assertFalse(result.contains("oldest-event"));
        assertTrue(result.indexOf("middle-event") < result.indexOf("newest-event"));
        long revision = log.revision();
        log.clear();
        assertTrue(log.revision() > revision);
        assertEquals("", log.render(4));
    }
    @Test public void errorClassificationDoesNotEchoCredentialsOrKeyMaterial() {
        String raw = "Auth fail password=TOP_SECRET passphrase=ANOTHER_SECRET -----BEGIN PRIVATE KEY-----";
        AppLog log = new AppLog(10);
        log.record(AppLog.ERROR, "test", AppLog.errorCategory(raw));
        String result = log.render(4);
        assertTrue(result.contains("Авторизация SSH"));
        assertFalse(result.contains("TOP_SECRET"));
        assertFalse(result.contains("ANOTHER_SECRET"));
        assertFalse(result.contains("PRIVATE KEY"));
    }
}
