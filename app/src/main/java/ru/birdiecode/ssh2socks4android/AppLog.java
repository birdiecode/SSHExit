package ru.birdiecode.ssh2socks4android;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;

/** Process-local bounded diagnostics. Callers must pass structured events, never credentials or raw SSH logs. */
final class AppLog {
    static final int ERROR = 0, WARN = 1, INFO = 2, DEBUG = 3, TRACE = 4;
    static final AppLog INSTANCE = new AppLog(1000);
    private final int capacity;
    private final ArrayDeque<Entry> entries = new ArrayDeque<>();
    private long revision;

    AppLog(int capacity) {
        if (capacity < 1) throw new IllegalArgumentException("Log capacity must be positive");
        this.capacity = capacity;
    }

    private static final class Entry {
        final long time;
        final int level;
        final String connection, message;
        Entry(int level, String connection, String message) {
            this.time = System.currentTimeMillis();
            this.level = level;
            this.connection = connection == null ? "app" : connection.substring(0, Math.min(8, connection.length()));
            this.message = message;
        }
    }

    synchronized void record(int level, String connection, String safeEvent) {
        if (level < ERROR || level > TRACE) throw new IllegalArgumentException("Invalid log level");
        if (entries.size() == capacity) entries.removeFirst();
        entries.addLast(new Entry(level, connection, safeEvent));
        revision++;
    }

    synchronized void clear() { entries.clear(); revision++; }
    synchronized long revision() { return revision; }

    synchronized String render(int verbosity) {
        if (verbosity < ERROR || verbosity > TRACE) throw new IllegalArgumentException("Invalid verbosity");
        SimpleDateFormat time = new SimpleDateFormat("HH:mm:ss.SSS", Locale.ROOT);
        String[] names = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
        StringBuilder result = new StringBuilder();
        for (Entry entry : entries) {
            if (entry.level > verbosity) continue;
            result.append(time.format(new Date(entry.time))).append(' ')
                    .append(names[entry.level]).append(" [").append(entry.connection).append("] ")
                    .append(entry.message).append('\n');
        }
        return result.toString();
    }

    /** Classifies an error without ever returning the possibly sensitive input text. */
    static String errorCategory(String detail) {
        String value = detail == null ? "" : detail.toLowerCase(Locale.ROOT);
        if (value.contains("fingerprint") || value.contains("hostkey")) return "Проверка host key";
        if (value.contains("парол") || value.contains("auth")) return "Авторизация SSH";
        if (value.contains("protect") || value.contains("ssh-сокет")) return "Защита SSH-сокета от VPN";
        if (value.contains("address already in use") || value.contains("bind")) return "Локальный порт занят";
        if (value.contains("permission") || value.contains("operation not permitted")) return "Недостаточно прав";
        if (value.contains("timeout") || value.contains("timed out")) return "Тайм-аут";
        if (value.contains("nft")) return "Настройка nftables";
        if (value.contains("tun")) return "Канал или настройка TUN";
        if (value.contains("refused")) return "Соединение отклонено";
        if (value.contains("unreachable") || value.contains("no route")) return "Сеть недоступна";
        return "Ошибка соединения";
    }

    private AppLog() { this(1000); }
}
