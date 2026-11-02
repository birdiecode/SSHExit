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
