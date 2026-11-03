package ru.birdiecode.ssh2socks4android;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

final class SshKeyStore {
    private static final String PREFS = "ssh_key_vault";
    private static final String KEYS = "keys";

    static synchronized List<SshKey> all(Context context) {
        migrateLegacyKeys(context);
        ArrayList<SshKey> keys = new ArrayList<>();
        try {
            JSONArray array = new JSONArray(prefs(context).getString(KEYS, "[]"));
            for (int i = 0; i < array.length(); i++) {
                JSONObject json = array.optJSONObject(i);
                if (json == null) continue;
                SshKey key = new SshKey();
                key.id = json.optString("id");
                key.name = json.optString("name");
                key.encryptedPrivateKey = json.optString("encryptedPrivateKey");
                key.encryptedPassphrase = json.optString("encryptedPassphrase");
                if (!key.id.isEmpty()) keys.add(key);
            }
        } catch (Exception ignored) {}
        return keys;
    }

    static synchronized SshKey get(Context context, String id) {
        for (SshKey key : all(context)) if (key.id.equals(id)) return key;
        return null;
    }

    static synchronized void save(Context context, SshKey key) {
        List<SshKey> keys = all(context);
        boolean replaced = false;
        for (int i = 0; i < keys.size(); i++) {
            if (keys.get(i).id.equals(key.id)) {
                keys.set(i, key);
                replaced = true;
                break;
            }
        }
        if (!replaced) keys.add(key);
        JSONArray array = new JSONArray();
        for (SshKey item : keys) array.put(toJson(item));
        prefs(context).edit().putString(KEYS, array.toString()).apply();
    }

    static synchronized boolean isUsed(Context context, String id) {
        for (Profile profile : ProfileStore.all(context)) {
            if (id.equals(profile.keyId) || id.equals(profile.jumpKeyId)) return true;
        }
        return false;
    }

    static synchronized void delete(Context context, String id) {
        List<SshKey> keys = all(context);
        JSONArray array = new JSONArray();
        for (SshKey key : keys) if (!key.id.equals(id)) array.put(toJson(key));
        prefs(context).edit().putString(KEYS, array.toString()).apply();
    }

    /** Moves encrypted inline keys from old host profiles into the shared vault once. */
    private static synchronized void migrateLegacyKeys(Context context) {
        SharedPreferences preferences = prefs(context);
        final String migratedFlag = "legacy_profile_keys_migrated_v1";
        if (preferences.getBoolean(migratedFlag, false)) return;
        try {
            List<SshKey> keys = new ArrayList<>();
            JSONArray savedKeys = new JSONArray(preferences.getString(KEYS, "[]"));
            for (int i = 0; i < savedKeys.length(); i++) {
                JSONObject json = savedKeys.optJSONObject(i);
                if (json == null) continue;
                SshKey key = new SshKey();
                key.id = json.optString("id");
                key.name = json.optString("name");
                key.encryptedPrivateKey = json.optString("encryptedPrivateKey");
                key.encryptedPassphrase = json.optString("encryptedPassphrase");
                if (!key.id.isEmpty()) keys.add(key);
            }

            boolean keysChanged = false;
            List<Profile> profiles = ProfileStore.all(context);
            List<Profile> changedProfiles = new ArrayList<>();
            for (Profile profile : profiles) {
                if (profile.encryptedKey == null || profile.encryptedKey.isEmpty()) continue;
                boolean alreadyPresent = false;
                for (SshKey existing : keys) {
                    if (profile.encryptedKey.equals(existing.encryptedPrivateKey)) {
                        alreadyPresent = true;
                        break;
                    }
                }
                if (!alreadyPresent) {
                    SshKey migrated = new SshKey(
                            (profile.name == null || profile.name.trim().isEmpty()
                                    ? "SSH" : profile.name) + " — импортированный ключ",
                            profile.encryptedKey,
                            profile.encryptedPassphrase == null ? "" : profile.encryptedPassphrase);
                    keys.add(migrated);
                    keysChanged = true;
                }
                profile.encryptedKey = "";
                profile.encryptedPassphrase = "";
                profile.keyId = "";
                changedProfiles.add(profile);
            }
            if (keysChanged) {
                JSONArray array = new JSONArray();
                for (SshKey key : keys) array.put(toJson(key));
                preferences.edit().putString(KEYS, array.toString()).apply();
            }
            for (Profile profile : changedProfiles) ProfileStore.save(context, profile);
            preferences.edit().putBoolean(migratedFlag, true).apply();
        } catch (Exception ignored) {
            // Leave the migration flag unset so the next launch can retry without data loss.
        }
    }

    private static JSONObject toJson(SshKey key) {
        JSONObject json = new JSONObject();
        try {
            json.put("id", key.id);
            json.put("name", key.name);
            json.put("encryptedPrivateKey", key.encryptedPrivateKey);
            json.put("encryptedPassphrase", key.encryptedPassphrase);
        } catch (Exception ignored) {}
        return json;
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private SshKeyStore() {}
}
