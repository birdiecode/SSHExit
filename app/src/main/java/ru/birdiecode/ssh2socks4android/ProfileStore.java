package ru.birdiecode.ssh2socks4android;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

final class ProfileStore {
    private static final String PREFS = "ssh_profiles";
    private static final String PROFILES = "profiles";
    private static final String STATUS = "service_status";
    private static final String STATUS_PROFILE = "service_profile";
    private static final String STATUS_DETAIL = "service_detail";
    private static final String PENDING_FINGERPRINT = "pending_fingerprint";

    static synchronized List<Profile> all(Context context) {
        ArrayList<Profile> profiles = new ArrayList<>();
        try {
            String encoded = prefs(context).getString(PROFILES, "[]");
            JSONArray array = new JSONArray(encoded);
            if (array == null) return profiles;
            for (int i = 0; i < array.length(); i++) {
                JSONObject json = array.optJSONObject(i);
                if (json == null) continue;
                Profile p = new Profile();
                p.id = json.optString("id");
                p.name = json.optString("name");
                p.host = json.optString("host");
                p.sshPort = json.optInt("sshPort", 22);
                p.username = json.optString("username");
                p.localPort = json.optInt("localPort", 1080);
                p.keyId = json.optString("keyId");
                p.encryptedKey = json.optString("encryptedKey");
                p.encryptedPassword = json.optString("encryptedPassword");
                p.encryptedPassphrase = json.optString("encryptedPassphrase");
                p.hostFingerprint = json.optString("hostFingerprint");
                p.jumpHost = json.optString("jumpHost");
                p.jumpPort = json.optInt("jumpPort", 22);
                p.jumpUsername = json.optString("jumpUsername");
                p.encryptedJumpPassword = json.optString("encryptedJumpPassword");
                p.jumpKeyId = json.optString("jumpKeyId");
                p.jumpFingerprint = json.optString("jumpFingerprint");
                if (!p.id.isEmpty()) profiles.add(p);
            }
        } catch (Exception ignored) {
            // A malformed preference should not crash the app; the user can recreate the profile.
        }
        return profiles;
    }

    static synchronized Profile get(Context context, String id) {
        for (Profile p : all(context)) if (p.id.equals(id)) return p;
        return null;
    }

    static synchronized void save(Context context, Profile profile) {
        List<Profile> profiles = all(context);
        boolean replaced = false;
        for (int i = 0; i < profiles.size(); i++) {
            if (profiles.get(i).id.equals(profile.id)) {
                profiles.set(i, profile);
                replaced = true;
                break;
            }
        }
        if (!replaced) profiles.add(profile);
        JSONArray array = new JSONArray();
        for (Profile p : profiles) array.put(toJson(p));
        prefs(context).edit().putString(PROFILES, array.toString()).apply();
    }

    static synchronized void delete(Context context, String id) {
        List<Profile> profiles = all(context);
        JSONArray array = new JSONArray();
        for (Profile p : profiles) if (!p.id.equals(id)) array.put(toJson(p));
        prefs(context).edit().putString(PROFILES, array.toString()).apply();
    }

    static synchronized void setStatus(Context context, String profileId, String status, String detail) {
        prefs(context).edit()
                .putString(STATUS_PROFILE, profileId == null ? "" : profileId)
                .putString(STATUS, status == null ? "IDLE" : status)
                .putString(STATUS_DETAIL, detail == null ? "" : detail)
                .apply();
    }

    static String status(Context context) {
        return prefs(context).getString(STATUS, "IDLE");
    }

    static String statusProfile(Context context) {
        return prefs(context).getString(STATUS_PROFILE, "");
    }

    static String statusDetail(Context context) {
        return prefs(context).getString(STATUS_DETAIL, "");
    }

    static void setPendingFingerprint(Context context, String fingerprint) {
        prefs(context).edit().putString(PENDING_FINGERPRINT, fingerprint == null ? "" : fingerprint).apply();
    }

    static String pendingFingerprint(Context context) {
        return prefs(context).getString(PENDING_FINGERPRINT, "");
    }

    private static JSONObject toJson(Profile p) {
        JSONObject json = new JSONObject();
        try {
            json.put("id", p.id);
            json.put("name", p.name);
            json.put("host", p.host);
            json.put("sshPort", p.sshPort);
            json.put("username", p.username);
            json.put("localPort", p.localPort);
            json.put("keyId", p.keyId);
            json.put("encryptedKey", p.encryptedKey);
            json.put("encryptedPassword", p.encryptedPassword);
            json.put("encryptedPassphrase", p.encryptedPassphrase);
            json.put("hostFingerprint", p.hostFingerprint);
            json.put("jumpHost", p.jumpHost);
            json.put("jumpPort", p.jumpPort);
            json.put("jumpUsername", p.jumpUsername);
            json.put("encryptedJumpPassword", p.encryptedJumpPassword);
            json.put("jumpKeyId", p.jumpKeyId);
            json.put("jumpFingerprint", p.jumpFingerprint);
        } catch (Exception ignored) {}
        return json;
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private ProfileStore() {}
}
