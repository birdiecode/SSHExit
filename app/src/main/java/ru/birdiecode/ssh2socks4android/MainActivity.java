package ru.birdiecode.ssh2socks4android;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class MainActivity extends Activity {
    private static final int REQUEST_KEY = 100;
    private static final int REQUEST_NOTIFICATIONS = 101;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Map<String, TextView> rowStatuses = new HashMap<>();
    private final Map<String, Button> rowActions = new HashMap<>();

    private LinearLayout list;
    private TextView overallStatus;
    private byte[] pendingVaultKey;
    private String pendingVaultKeyName = "";
    private String promptedFingerprint = "";

    private final Runnable poll = new Runnable() {
        @Override public void run() {
            refreshStatuses();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(0xFFF5F7FA);
        getWindow().setNavigationBarColor(0xFFF5F7FA);
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQUEST_NOTIFICATIONS);
        }

        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setBackgroundColor(0xFFF5F7FA);
        page.setPadding(dp(20), dp(20), dp(20), dp(12));

        TextView title = text("SSH2SOCKS", 28, 0xFF152033, true);
        page.addView(title);

        TextView subtitle = text("SSH connection profiles and a local SOCKS5 proxy", 14, 0xFF65728A, false);
        LinearLayout.LayoutParams subtitleParams = params(-1, -2);
        subtitleParams.topMargin = dp(5);
        page.addView(subtitle, subtitleParams);

        overallStatus = text("No active tunnel", 14, 0xFF33415C, true);
        LinearLayout.LayoutParams statusParams = params(-1, -2);
        statusParams.topMargin = dp(16);
        page.addView(overallStatus, statusParams);

        Button keyVault = new Button(this);
        keyVault.setText("SSH keys");
        keyVault.setOnClickListener(v -> showKeyManager());
        LinearLayout.LayoutParams vaultParams = params(-1, -2);
        vaultParams.topMargin = dp(10);
        page.addView(keyVault, vaultParams);

        Button add = new Button(this);
        add.setText("Add connection");
        add.setOnClickListener(v -> showEditor(null));
        LinearLayout.LayoutParams addParams = params(-1, -2);
        addParams.topMargin = dp(12);
        page.addView(add, addParams);

        ScrollView scroll = new ScrollView(this);
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(list);
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(-1, 0, 1f);
        scrollParams.topMargin = dp(12);
        page.addView(scroll, scrollParams);

        TextView help = text("The proxy listens only on this phone at 127.0.0.1. Set a SOCKS5-aware app to the shown port.", 12, 0xFF65728A, false);
        LinearLayout.LayoutParams helpParams = params(-1, -2);
        helpParams.topMargin = dp(8);
        page.addView(help, helpParams);

        setContentView(page);
        renderProfiles();
    }

    @Override protected void onResume() {
        super.onResume();
        handler.removeCallbacks(poll);
        handler.post(poll);
    }

    @Override protected void onPause() {
        handler.removeCallbacks(poll);
        super.onPause();
    }

    private void renderProfiles() {
        if (list == null) return;
        list.removeAllViews();
        rowStatuses.clear();
        rowActions.clear();

        List<Profile> profiles = ProfileStore.all(this);
        if (profiles.isEmpty()) {
            TextView empty = text("No connections yet. Add an SSH profile and choose password or key authentication.", 14, 0xFF65728A, false);
            empty.setGravity(Gravity.CENTER);
            empty.setPadding(dp(16), dp(32), dp(16), dp(32));
            list.addView(empty);
            return;
        }

        for (Profile profile : profiles) {
            LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setBackgroundColor(0xFFFFFFFF);
            card.setPadding(dp(16), dp(14), dp(16), dp(12));
            LinearLayout.LayoutParams cardParams = params(-1, -2);
            cardParams.bottomMargin = dp(10);
            list.addView(card, cardParams);

            TextView name = text(profile.name.isEmpty() ? profile.host : profile.name, 18, 0xFF152033, true);
            card.addView(name);
            String route = profile.jumpHost == null || profile.jumpHost.trim().isEmpty()
                    ? "" : "  ·  via " + profile.jumpHost + ":" + profile.jumpPort;
            TextView endpoint = text(profile.username + "@" + profile.host + ":" + profile.sshPort
                    + route + "  ·  SOCKS5 : " + profile.localPort, 13, 0xFF65728A, false);
            LinearLayout.LayoutParams endpointParams = params(-1, -2);
            endpointParams.topMargin = dp(4);
            card.addView(endpoint, endpointParams);

            TextView state = text("", 13, 0xFF33415C, false);
            LinearLayout.LayoutParams stateParams = params(-1, -2);
            stateParams.topMargin = dp(9);
            card.addView(state, stateParams);
            rowStatuses.put(profile.id, state);

            LinearLayout buttons = new LinearLayout(this);
            buttons.setOrientation(LinearLayout.HORIZONTAL);
            LinearLayout.LayoutParams buttonsParams = params(-1, -2);
            buttonsParams.topMargin = dp(6);
            card.addView(buttons, buttonsParams);

            Button action = new Button(this);
            action.setOnClickListener(v -> toggle(profile));
            buttons.addView(action, new LinearLayout.LayoutParams(0, -2, 1f));
            rowActions.put(profile.id, action);

            Button edit = new Button(this);
            edit.setText("Edit");
            edit.setOnClickListener(v -> showEditor(profile));
            buttons.addView(edit, new LinearLayout.LayoutParams(0, -2, 1f));

            Button delete = new Button(this);
            delete.setText("Delete");
            delete.setOnClickListener(v -> confirmDelete(profile));
            buttons.addView(delete, new LinearLayout.LayoutParams(0, -2, 1f));
        }
        refreshStatuses();
    }

    private void refreshStatuses() {
        if (overallStatus == null) return;
        String status = ProfileStore.status(this);
        String profileId = ProfileStore.statusProfile(this);
        String detail = ProfileStore.statusDetail(this);
        Profile active = ProfileStore.get(this, profileId);

        if ("CONNECTED".equals(status)) {
            overallStatus.setText("Connected · SOCKS5 127.0.0.1:" + (active == null ? "" : active.localPort));
            overallStatus.setTextColor(0xFF167447);
        } else if ("CONNECTING".equals(status)) {
            overallStatus.setText(detail.isEmpty() ? "Connecting…" : detail);
            overallStatus.setTextColor(0xFF8A5A00);
        } else if ("NEEDS_TRUST".equals(status)) {
            overallStatus.setText("Review the SSH server fingerprint");
            overallStatus.setTextColor(0xFF8A5A00);
            askToTrust(profileId, detail);
        } else if ("ERROR".equals(status)) {
            overallStatus.setText("Connection error · " + detail);
            overallStatus.setTextColor(0xFFB42318);
        } else {
            overallStatus.setText("No active tunnel");
            overallStatus.setTextColor(0xFF33415C);
        }

        for (String id : rowStatuses.keySet()) {
            TextView row = rowStatuses.get(id);
            Button action = rowActions.get(id);
            if (row == null || action == null) continue;
            if (!id.equals(profileId)) {
                row.setText("Ready");
                action.setText("Connect");
            } else {
                row.setText(detail.isEmpty() ? status : detail);
                boolean running = "CONNECTED".equals(status) || "CONNECTING".equals(status) || "NEEDS_TRUST".equals(status);
                action.setText(running ? "Stop" : "Connect");
            }
        }
    }

    private void askToTrust(String profileId, String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty() || fingerprint.equals(promptedFingerprint)) return;
        promptedFingerprint = fingerprint;
        Profile profile = ProfileStore.get(this, profileId);
        if (profile == null) return;
        boolean isJump = fingerprint.startsWith("JUMP:");
        String shownFingerprint = fingerprint.startsWith("JUMP:") || fingerprint.startsWith("TARGET:")
                ? fingerprint.substring(fingerprint.indexOf(':') + 1) : fingerprint;
        String server = isJump
                ? profile.jumpUsername + "@" + profile.jumpHost + ":" + profile.jumpPort
                : profile.username + "@" + profile.host + ":" + profile.sshPort;
        new AlertDialog.Builder(this)
                .setTitle("Trust SSH server?")
                .setMessage("Server: " + server
                        + "\n\nFingerprint:\n" + shownFingerprint
                        + "\n\nCompare this value with the server administrator over a trusted channel before accepting.")
                .setPositiveButton("Trust and connect", (dialog, which) -> {
                    promptedFingerprint = "";
                    startTunnelAction(SshTunnelService.ACTION_TRUST, profileId);
                })
                .setNegativeButton("Cancel", (dialog, which) -> {
                    promptedFingerprint = "";
                    startTunnelAction(SshTunnelService.ACTION_STOP, profileId);
                })
                .show();
    }

    private void toggle(Profile profile) {
        String status = ProfileStore.status(this);
        String activeId = ProfileStore.statusProfile(this);
        if (profile.id.equals(activeId) && ("CONNECTED".equals(status)
                || "CONNECTING".equals(status) || "NEEDS_TRUST".equals(status))) {
            startTunnelAction(SshTunnelService.ACTION_STOP, profile.id);
        } else {
            startTunnelAction(SshTunnelService.ACTION_CONNECT, profile.id);
        }
    }

    private void startTunnelAction(String action, String profileId) {
        Intent intent = new Intent(this, SshTunnelService.class);
        intent.setAction(action);
        intent.putExtra(SshTunnelService.EXTRA_PROFILE_ID, profileId);
        try {
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent);
            else startService(intent);
        } catch (Exception e) {
            Toast.makeText(this, "Could not start tunnel: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void confirmDelete(Profile profile) {
        new AlertDialog.Builder(this)
                .setTitle("Delete " + profile.name + "?")
                .setMessage("The saved encrypted credentials and profile will be removed.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Delete", (dialog, which) -> {
                    if (profile.id.equals(ProfileStore.statusProfile(this))) {
                        startTunnelAction(SshTunnelService.ACTION_STOP, profile.id);
                    }
                    ProfileStore.delete(this, profile.id);
                    renderProfiles();
                })
                .show();
    }

    private void showEditor(Profile existing) {
        final Profile profile = existing == null
                ? new Profile("", "", 22, "", 1080)
                : copy(existing);

        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(20), dp(8), dp(20), dp(4));

        EditText name = input("Profile name", profile.name, InputType.TYPE_CLASS_TEXT);
        EditText host = input("SSH host or IP", profile.host, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        EditText sshPort = input("SSH port", String.valueOf(profile.sshPort), InputType.TYPE_CLASS_NUMBER);
        EditText username = input("Username", profile.username, InputType.TYPE_CLASS_TEXT);
        EditText localPort = input("Local SOCKS5 port", String.valueOf(profile.localPort), InputType.TYPE_CLASS_NUMBER);
        EditText sshPassword = input("SSH password (blank keeps saved value)", "", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        TextView jumpTitle = text("Jump server · ProxyJump (-J)", 16, 0xFF152033, true);
        LinearLayout.LayoutParams jumpTitleParams = params(-1, -2);
        jumpTitleParams.topMargin = dp(14);
        form.addView(jumpTitle, jumpTitleParams);

        TextView jumpTitle = text("Подключаться через", 16, 0xFF152033, true);
        LinearLayout.LayoutParams jumpTitleParams = params(-1, -2);
        jumpTitleParams.topMargin = dp(14);
        form.addView(jumpTitle, jumpTitleParams);

        ArrayList<Profile> jumpOptions = new ArrayList<>();
        jumpOptions.add(null);
        String legacyJumpId = profile.jumpProfileId == null ? "" : profile.jumpProfileId;
        List<Profile> availableHosts = ProfileStore.all(this);
        for (Profile candidate : availableHosts) {
            if (candidate.id.equals(profile.id)) continue;
            if (legacyJumpId.isEmpty() && profile.jumpHost != null
                    && candidate.host.equalsIgnoreCase(profile.jumpHost)
                    && candidate.sshPort == profile.jumpPort
                    && candidate.username.equals(profile.jumpUsername)) {
                legacyJumpId = candidate.id;
            }
            jumpOptions.add(candidate);
        }
        ArrayList<String> jumpLabels = new ArrayList<>();
        jumpLabels.add("Напрямую");
        int jumpSelection = 0;
        for (int i = 1; i < jumpOptions.size(); i++) {
            Profile candidate = jumpOptions.get(i);
            jumpLabels.add(candidate.name + " · " + candidate.username + "@" + candidate.host);
            if (candidate.id.equals(legacyJumpId)) jumpSelection = i;
        }
        Spinner jumpProfile = new Spinner(this);
        jumpProfile.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item,
                jumpLabels));
        jumpProfile.setSelection(jumpSelection);
        form.addView(jumpProfile);
        EditText sshPassword = input("SSH password (optional; blank keeps saved value)", "",
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        form.addView(sshPassword);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(form);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(existing == null ? "Add connection" : "Edit connection")
                .setView(scroll)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Save", null)
                .create();

        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                String hostValue = host.getText().toString().trim();
                String userValue = username.getText().toString().trim();
                int sshPortValue = parsePort(sshPort.getText().toString(), "SSH port");
                int localPortValue = parsePort(localPort.getText().toString(), "SOCKS5 port");
                if (hostValue.isEmpty() || userValue.isEmpty()) throw new IllegalArgumentException("Host and username are required");
                if (localPortValue < 1024) throw new IllegalArgumentException("SOCKS5 port must be 1024–65535");

                Profile selectedJump = jumpOptions.get(jumpProfile.getSelectedItemPosition());
                String selectedJumpId = selectedJump == null ? "" : selectedJump.id;
                if (!selectedJumpId.isEmpty() && wouldCreateCycle(profile.id, selectedJumpId)) {
                    throw new IllegalArgumentException("This ProxyJump would create a cycle");
                }

                profile.name = name.getText().toString().trim();
                if (profile.name.isEmpty()) profile.name = hostValue;
                profile.host = hostValue;
                profile.username = userValue;
                profile.sshPort = sshPortValue;
                profile.localPort = localPortValue;
                profile.jumpProfileId = selectedJumpId;
                // Clear inline jump data after migrating to a host reference.
                profile.jumpHost = "";
                profile.jumpUsername = "";
                profile.encryptedJumpPassword = "";
                profile.jumpKeyId = "";
                profile.jumpFingerprint = "";


                String password = sshPassword.getText().toString();
                if (!password.isEmpty()) profile.encryptedPassword = KeyVault.encrypt(password.getBytes(StandardCharsets.UTF_8));

                ProfileStore.save(this, profile);
                dialog.dismiss();
                renderProfiles();
            } catch (Exception e) {
                Toast.makeText(this, e.getMessage() == null ? "Could not save profile" : e.getMessage(), Toast.LENGTH_LONG).show();
            }
        }));
        dialog.show();
    }

    private boolean wouldCreateCycle(String profileId, String jumpId) {
        java.util.HashSet<String> seen = new java.util.HashSet<>();
        String current = jumpId;
        while (current != null && !current.isEmpty()) {
            if (current.equals(profileId) || !seen.add(current)) return true;
            Profile node = ProfileStore.get(this, current);
            if (node == null) return false;
            current = node.jumpProfileId;
        }
        return false;
    }

    private int parsePort(String value, String label) {
        int port = Integer.parseInt(value.trim());
        if (port < 1 || port > 65535) throw new IllegalArgumentException(label + " must be 1–65535");
        return port;
    }

    private String keyLabel(Profile profile) {
        if (profile.keyId != null && !profile.keyId.isEmpty()) {
            SshKey key = SshKeyStore.get(this, profile.keyId);
            if (key != null) return "Saved target key: " + key.name;
        }
        if (profile.encryptedKey != null && !profile.encryptedKey.isEmpty()) return "Legacy key attached to this profile";
        return "No target key selected";
    }

    private String jumpKeyLabel(Profile profile) {
        if (profile.jumpKeyId != null && !profile.jumpKeyId.isEmpty()) {
            SshKey key = SshKeyStore.get(this, profile.jumpKeyId);
            if (key != null) return "Saved jump key: " + key.name;
        }
        return "No jump server key selected";
    }

    private interface KeySelectionListener {
        void onSelected(SshKey key);
    }

    private void showKeyPicker(String selectedId, boolean allowNone, KeySelectionListener listener) {
        List<SshKey> keys = SshKeyStore.all(this);
        ArrayList<SshKey> options = new ArrayList<>();
        ArrayList<String> labels = new ArrayList<>();
        if (allowNone) {
            options.add(null);
            labels.add("No key");
        }
        for (SshKey key : keys) {
            options.add(key);
            labels.add(key.name);
        }
        if (keys.isEmpty()) {
            Toast.makeText(this, "Import a key from the SSH keys screen first", Toast.LENGTH_LONG).show();
            return;
        }
        int selectedIndex = 0;
        for (int i = 0; i < options.size(); i++) {
            SshKey option = options.get(i);
            if (option != null && option.id.equals(selectedId)) selectedIndex = i;
        }
        new AlertDialog.Builder(this)
                .setTitle("Select private key")
                .setSingleChoiceItems(labels.toArray(new String[0]), selectedIndex, (dialog, which) -> {
                    listener.onSelected(options.get(which));
                    dialog.dismiss();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showKeyManager() {
        List<SshKey> keys = SshKeyStore.all(this);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(20), dp(8), dp(20), dp(4));

        if (keys.isEmpty()) {
            TextView empty = text("No saved keys. Import a private key to reuse it across SSH profiles.", 14, 0xFF65728A, false);
            body.addView(empty);
        } else {
            for (SshKey key : keys) {
                LinearLayout row = new LinearLayout(this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                TextView label = text(key.name, 15, 0xFF152033, false);
                row.addView(label, new LinearLayout.LayoutParams(0, -2, 1f));
                Button delete = new Button(this);
                delete.setText("Delete");
                delete.setOnClickListener(v -> {
                    if (SshKeyStore.isUsed(this, key.id)) {
                        Toast.makeText(this, "This key is used by a connection profile", Toast.LENGTH_LONG).show();
                        return;
                    }
                    new AlertDialog.Builder(this)
                            .setTitle("Delete key?")
                            .setMessage("The encrypted private key will be removed from the vault.")
                            .setNegativeButton("Cancel", null)
                            .setPositiveButton("Delete", (d, w) -> {
                                SshKeyStore.delete(this, key.id);
                                showKeyManager();
                            })
                            .show();
                });
                row.addView(delete);
                body.addView(row);
            }
        }

        ScrollView scroll = new ScrollView(this);
        scroll.addView(body);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("SSH key vault")
                .setView(scroll)
                .setNegativeButton("Done", null)
                .setPositiveButton("Import private key", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            dialog.dismiss();
            Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            picker.addCategory(Intent.CATEGORY_OPENABLE);
            picker.setType("*/*");
            startActivityForResult(picker, REQUEST_KEY);
        }));
        dialog.show();
    }

    private void showSaveKeyDialog() {
        if (pendingVaultKey == null) return;
        EditText name = input("Key name", pendingVaultKeyName, InputType.TYPE_CLASS_TEXT);
        EditText passphrase = input("Key passphrase (if encrypted)", "", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(20), dp(8), dp(20), dp(4));
        form.addView(name);
        form.addView(passphrase);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Save private key")
                .setView(form)
                .setNegativeButton("Cancel", (d, w) -> pendingVaultKey = null)
                .setPositiveButton("Save", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                String keyName = name.getText().toString().trim();
                if (keyName.isEmpty()) keyName = "SSH key";
                String secret = passphrase.getText().toString();
                SshKey key = new SshKey(
                        keyName,
                        KeyVault.encrypt(pendingVaultKey),
                        secret.isEmpty() ? "" : KeyVault.encrypt(secret.getBytes(StandardCharsets.UTF_8)));
                SshKeyStore.save(this, key);
                pendingVaultKey = null;
                dialog.dismiss();
                Toast.makeText(this, "Key saved in the vault", Toast.LENGTH_SHORT).show();
                showKeyManager();
            } catch (Exception e) {
                Toast.makeText(this, e.getMessage() == null ? "Could not save key" : e.getMessage(), Toast.LENGTH_LONG).show();
            }
        }));
        dialog.show();
    }

    private Profile copy(Profile source) {
        Profile p = new Profile(source.name, source.host, source.sshPort, source.username, source.localPort);
        p.id = source.id;
        p.keyId = source.keyId;
        p.encryptedKey = source.encryptedKey;
        p.encryptedPassphrase = source.encryptedPassphrase;
        p.encryptedPassword = source.encryptedPassword;
        p.hostFingerprint = source.hostFingerprint;
        p.jumpHost = source.jumpHost;
        p.jumpPort = source.jumpPort;
        p.jumpUsername = source.jumpUsername;
        p.encryptedJumpPassword = source.encryptedJumpPassword;
        p.jumpKeyId = source.jumpKeyId;
        p.jumpFingerprint = source.jumpFingerprint;
        return p;
    }

    private EditText input(String hint, String value, int inputType) {
        EditText edit = new EditText(this);
        edit.setSingleLine(true);
        edit.setHint(hint);
        edit.setText(value);
        edit.setInputType(inputType);
        return edit;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_KEY || resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        try (InputStream input = getContentResolver().openInputStream(uri);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            if (input == null) throw new IllegalStateException("Could not read selected file");
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
            pendingVaultKey = output.toByteArray();
            String filename = uri.getLastPathSegment();
            pendingVaultKeyName = filename == null || filename.trim().isEmpty() ? "SSH key" : filename;
            showSaveKeyDialog();
        } catch (Exception e) {
            Toast.makeText(this, "Could not read key: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private TextView text(String value, int sizeSp, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sizeSp);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private LinearLayout.LayoutParams params(int width, int height) {
        return new LinearLayout.LayoutParams(width, height);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
