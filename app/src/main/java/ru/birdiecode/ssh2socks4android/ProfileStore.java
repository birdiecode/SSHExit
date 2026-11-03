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
    private static final String GRAPH_MIGRATED = "graph_migrated_v1";

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
                p.connectionMode = json.optString("connectionMode", "SOCKS5");
                p.vpnIpv4 = json.optBoolean("vpnIpv4", true);
                p.vpnIpv6 = json.optBoolean("vpnIpv6", false);
                p.vpnIpv6Prefix = json.optString("vpnIpv6Prefix", "");
                p.vpnMtu = json.optInt("vpnMtu", 1400);
                p.vpnDnsServers = json.optString("vpnDnsServers", "1.1.1.1");
                p.vpnFullTunnel = json.optBoolean("vpnFullTunnel", true);
                p.vpnRoutes = json.optString("vpnRoutes", "");
                p.vpnRoutePriority = json.optInt("vpnRoutePriority", 0);
                p.vpnPrimary = json.optBoolean("vpnPrimary", false);
                p.vpnFailover = json.optBoolean("vpnFailover", false);
                p.vpnAutoReconnect = json.optBoolean("vpnAutoReconnect", true);
                p.vpnExternalInterface = json.optString("vpnExternalInterface", "");
                p.serverSkipConfirmation = json.optBoolean("serverSkipConfirmation", false);
                p.serverManageIpv4Forwarding = json.optBoolean("serverManageIpv4Forwarding", true);
                p.serverManageIpv6Forwarding = json.optBoolean("serverManageIpv6Forwarding", true);
                p.serverNatIpv4 = json.optBoolean("serverNatIpv4", true);
                p.serverAcceptOutbound = json.optBoolean("serverAcceptOutbound", true);
                p.serverAcceptReturn = json.optBoolean("serverAcceptReturn", true);
                p.keyId = json.optString("keyId");
                p.encryptedKey = json.optString("encryptedKey");
                p.encryptedPassword = json.optString("encryptedPassword");
                p.encryptedPassphrase = json.optString("encryptedPassphrase");
                p.hostFingerprint = json.optString("hostFingerprint");
                p.observedFingerprint = json.optString("observedFingerprint");
                p.jumpProfileId = json.optString("jumpProfileId");
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
        if (!prefs(context).getBoolean(GRAPH_MIGRATED, false)) {
            migrateLegacyJumpSettings(context, profiles);
        }
        return profiles;
    }

    private static synchronized void migrateLegacyJumpSettings(Context context, List<Profile> profiles) {
        boolean changed = false;
        for (int profileIndex = 0; profileIndex < profiles.size(); profileIndex++) {
            Profile source = profiles.get(profileIndex);
            if (source.jumpProfileId != null && !source.jumpProfileId.isEmpty()) continue;
            if (source.jumpHost == null || source.jumpHost.trim().isEmpty()) continue;

            Profile jump = null;
            for (Profile candidate : profiles) {
                if (!candidate.id.equals(source.id)
                        && candidate.host.equalsIgnoreCase(source.jumpHost)
                        && candidate.sshPort == source.jumpPort
                        && candidate.username.equals(source.jumpUsername)) {
                    jump = candidate;
                    break;
                }
            }
            if (jump == null) {
                jump = new Profile("Jump · " + source.jumpHost, source.jumpHost, source.jumpPort,
                        source.jumpUsername == null ? "" : source.jumpUsername, 1081);
                profiles.add(jump);
            }
            // Preserve credentials and pins stored inline on the old target profile.
            if ((jump.encryptedPassword == null || jump.encryptedPassword.isEmpty())
                    && source.encryptedJumpPassword != null && !source.encryptedJumpPassword.isEmpty()) {
                jump.encryptedPassword = source.encryptedJumpPassword;
            }
            if ((jump.hostFingerprint == null || jump.hostFingerprint.isEmpty())
                    && source.jumpFingerprint != null && !source.jumpFingerprint.isEmpty()) {
                jump.hostFingerprint = source.jumpFingerprint;
            }
            source.jumpProfileId = jump.id;
            source.jumpHost = "";
            source.jumpUsername = "";
            source.encryptedJumpPassword = "";
            source.jumpKeyId = "";
            source.jumpFingerprint = "";
            changed = true;
        }
        SharedPreferences.Editor editor = prefs(context).edit().putBoolean(GRAPH_MIGRATED, true);
        if (changed) {
            JSONArray array = new JSONArray();
            for (Profile profile : profiles) array.put(toJson(profile));
            editor.putString(PROFILES, array.toString());
        }
        editor.apply();
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

    static synchronized List<Profile> dependents(Context context, String id) {
        ArrayList<Profile> result = new ArrayList<>();
        for (Profile p : all(context)) if (id.equals(p.jumpProfileId)) result.add(p);
        return result;
    }

    static synchronized void delete(Context context, String id) {
        List<Profile> profiles = all(context);
        JSONArray array = new JSONArray();
        for (Profile p : profiles) {
            if (p.id.equals(id)) continue;
            if (id.equals(p.jumpProfileId)) p.jumpProfileId = "";
            array.put(toJson(p));
        }
        prefs(context).edit().putString(PROFILES, array.toString()).apply();
    }

    static synchronized void setStatus(Context context, String profileId, String status, String detail) {
        prefs(context).edit()
                .putString("status." + profileId, status == null ? "IDLE" : status)
                .putString("detail." + profileId, detail == null ? "" : detail)
                .putString(STATUS_PROFILE, profileId == null ? "" : profileId)
                .putString(STATUS, status == null ? "IDLE" : status)
                .putString(STATUS_DETAIL, detail == null ? "" : detail)
                .apply();
    }

    static String status(Context context, String profileId) {
        return prefs(context).getString("status." + profileId, "IDLE");
    }

    static String statusDetail(Context context, String profileId) {
        return prefs(context).getString("detail." + profileId, "");
    }

    static synchronized void resetConnectionStatuses(Context context) {
        SharedPreferences.Editor editor = prefs(context).edit();
        for (String key : prefs(context).getAll().keySet()) {
            if (key.startsWith("status.") || key.startsWith("detail.")) editor.remove(key);
        }
        editor.putString(STATUS, "IDLE").putString(STATUS_PROFILE, "")
                .putString(STATUS_DETAIL, "").putString(PENDING_FINGERPRINT, "").apply();
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
            json.put("connectionMode", p.connectionMode);
            json.put("vpnIpv4", p.vpnIpv4);
            json.put("vpnIpv6", p.vpnIpv6);
            json.put("vpnIpv6Prefix", p.vpnIpv6Prefix);
            json.put("vpnMtu", p.vpnMtu);
            json.put("vpnDnsServers", p.vpnDnsServers);
            json.put("vpnFullTunnel", p.vpnFullTunnel);
            json.put("vpnRoutes", p.vpnRoutes);
            json.put("vpnRoutePriority", p.vpnRoutePriority);
            json.put("vpnPrimary", p.vpnPrimary);
            json.put("vpnFailover", p.vpnFailover);
            json.put("vpnAutoReconnect", p.vpnAutoReconnect);
            json.put("vpnExternalInterface", p.vpnExternalInterface);
            json.put("serverSkipConfirmation", p.serverSkipConfirmation);
            json.put("serverManageIpv4Forwarding", p.serverManageIpv4Forwarding);
            json.put("serverManageIpv6Forwarding", p.serverManageIpv6Forwarding);
            json.put("serverNatIpv4", p.serverNatIpv4);
            json.put("serverAcceptOutbound", p.serverAcceptOutbound);
            json.put("serverAcceptReturn", p.serverAcceptReturn);
            json.put("keyId", p.keyId);
            json.put("encryptedKey", p.encryptedKey);
            json.put("encryptedPassword", p.encryptedPassword);
            json.put("encryptedPassphrase", p.encryptedPassphrase);
            json.put("hostFingerprint", p.hostFingerprint);
            json.put("observedFingerprint", p.observedFingerprint);
            json.put("jumpProfileId", p.jumpProfileId);
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
