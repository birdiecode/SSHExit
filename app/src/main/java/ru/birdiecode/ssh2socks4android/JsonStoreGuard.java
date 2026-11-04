package ru.birdiecode.ssh2socks4android;

import android.content.SharedPreferences;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/** Strict JSON reads and checked, backed-up writes. Existing payload format stays unchanged. */
final class JsonStoreGuard {
    static final class StorageException extends IllegalStateException {
        StorageException(String message) { super(message); }
    }
    private static final Set<String> logged = new HashSet<>();
    private static final Set<SharedPreferences> failedWrites =
            java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());

    static JSONArray read(SharedPreferences prefs, String key, JSONObject schema, String label) {
        try {
            if (prefs.contains(key) && !(prefs.getAll().get(key) instanceof String))
                throw new IllegalArgumentException();
            return validate(prefs.getString(key, "[]"), schema);
        } catch (Exception error) {
            preserveCorrupt(prefs, key);
            throw problem(label, "повреждено. Запись заблокирована; исходные данные сохранены. Не очищайте данные приложения.");
        }
    }

    private static JSONArray validate(String encoded, JSONObject schema) throws Exception {
        // JSONTokener rejects trailing non-whitespace text as well as malformed arrays.
        org.json.JSONTokener parser = new org.json.JSONTokener(encoded);
        Object root = parser.nextValue();
        if (!(root instanceof JSONArray) || parser.nextClean() != 0) throw new IllegalArgumentException();
        JSONArray array = (JSONArray) root;
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < array.length(); i++) {
            JSONObject item = array.getJSONObject(i);
            Object id = item.get("id");
            if (!(id instanceof String) || ((String) id).trim().isEmpty() || !ids.add((String) id))
                throw new IllegalArgumentException();
            Iterator<String> fields = item.keys();
            while (fields.hasNext()) {
                String field = fields.next();
                // Unknown fields may belong to a newer schema: never silently erase them.
                if (!schema.has(field)) throw new IllegalArgumentException();
                Object expected = schema.get(field), actual = item.get(field);
                if (expected instanceof String ? !(actual instanceof String)
                        : expected instanceof Boolean ? !(actual instanceof Boolean)
                        : expected instanceof Number ? !(actual instanceof Number)
                        : true) throw new IllegalArgumentException();
                if (actual instanceof Number) {
                    double number = ((Number) actual).doubleValue();
                    if (!Double.isFinite(number) || number != ((Number) actual).intValue())
                        throw new IllegalArgumentException();
                }
            }
        }
        return array;
    }

    static boolean flag(SharedPreferences prefs, String key, String label) {
        try { return prefs.getBoolean(key, false); }
        catch (Exception error) { throw problem(label, "содержит некорректную отметку миграции. Запись заблокирована."); }
    }

    static synchronized void write(SharedPreferences prefs, String key, JSONArray data,
            JSONObject schema, String label, String migrationFlag) {
        if (failedWrites.contains(prefs)) throw problem(label,
                "недоступно для записи после ошибки диска. Перезапустите приложение после устранения причины.");
        read(prefs, key, schema, label); // Never overwrite unreadable source, even with an empty list.
        String encoded = data.toString();
        try { validate(encoded, schema); }
        catch (Exception error) { throw problem(label, "не сохранено: некорректные данные."); }
        Map<String, ?> before = prefs.getAll();
        SharedPreferences.Editor editor = prefs.edit()
                .putString(key + ".last_good", prefs.getString(key, "[]"))
                .putString(key, encoded);
        if (migrationFlag != null) editor.putBoolean(migrationFlag, true);
        if (!editor.commit()) {
            failedWrites.add(prefs);
            // commit(false) can still change the process-local preferences: restore them too.
            SharedPreferences.Editor rollback = prefs.edit();
            restore(rollback, before, key);
            restore(rollback, before, key + ".last_good");
            if (migrationFlag != null) restore(rollback, before, migrationFlag);
            rollback.commit();
            throw problem(label, "не сохранено: ошибка записи. Изменения отменены; дальнейшая запись заблокирована.");
        }
    }

    private static void restore(SharedPreferences.Editor editor, Map<String, ?> before, String key) {
        Object value = before.get(key);
        if (value instanceof String) editor.putString(key, (String) value);
        else if (value instanceof Boolean) editor.putBoolean(key, (Boolean) value);
        else editor.remove(key);
    }

    private static void preserveCorrupt(SharedPreferences prefs, String key) {
        String backup = key + ".corrupt_first";
        try {
            if (prefs.contains(backup)) return;
            Object raw = prefs.getAll().get(key);
            SharedPreferences.Editor editor = prefs.edit();
            if (raw instanceof String) editor.putString(backup, (String) raw);
            else if (raw instanceof Integer) editor.putInt(backup, (Integer) raw);
            else if (raw instanceof Boolean) editor.putBoolean(backup, (Boolean) raw);
            else if (raw instanceof Long) editor.putLong(backup, (Long) raw);
            else if (raw instanceof Float) editor.putFloat(backup, (Float) raw);
            else return;
            if (!editor.commit()) problem("Хранилище", "не удалось записать резервную копию; оригинал не изменён.");
        } catch (Exception ignored) { /* The original payload is never replaced. */ }
    }

    static synchronized StorageException problem(String label, String safeDetail) {
        String message = label + ": " + safeDetail;
        if (logged.add(message)) AppLog.INSTANCE.record(AppLog.ERROR, "storage", message);
        return new StorageException(message);
    }
    private JsonStoreGuard() {}
}
