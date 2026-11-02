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
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
    private byte[] pendingKey;
    private String pendingKeyName = "";
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
            TextView empty = text("No connections yet. Add a profile and import an SSH private key.", 14, 0xFF65728A, false);
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
            TextView endpoint = text(profile.username + "@" + profile.host + ":" + profile.sshPort
                    + "  ·  SOCKS5 : " + profile.localPort, 13, 0xFF65728A, false);
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
        new AlertDialog.Builder(this)
                .setTitle("Trust SSH server?")
                .setMessage("Server: " + profile.host + ":" + profile.sshPort
                        + "\n\nFingerprint:\n" + fingerprint
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
                .setMessage("The saved encrypted key and profile will be removed.")
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
        pendingKey = null;
        pendingKeyName = "";
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
        EditText passphrase = input("Private key passphrase (blank keeps saved value)", "", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

        form.addView(name);
        form.addView(host);
        form.addView(sshPort);
        form.addView(username);
        form.addView(localPort);
        form.addView(passphrase);

        TextView keyLabel = text(existing == null || existing.encryptedKey.isEmpty()
                ? "No private key selected" : "Saved private key is encrypted on this device", 12, 0xFF65728A, false);
        LinearLayout.LayoutParams keyLabelParams = params(-1, -2);
        keyLabelParams.topMargin = dp(8);
        form.addView(keyLabel, keyLabelParams);

        Button importKey = new Button(this);
        importKey.setText("Choose private key");
        importKey.setOnClickListener(v -> {
            Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            picker.addCategory(Intent.CATEGORY_OPENABLE);
            picker.setType("*/*");
            startActivityForResult(picker, REQUEST_KEY);
        });
        form.addView(importKey);

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
                int sshPortValue = Integer.parseInt(sshPort.getText().toString().trim());
                int localPortValue = Integer.parseInt(localPort.getText().toString().trim());
                if (hostValue.isEmpty() || userValue.isEmpty()) throw new IllegalArgumentException("Host and username are required");
                if (sshPortValue < 1 || sshPortValue > 65535) throw new IllegalArgumentException("SSH port must be 1–65535");
                if (localPortValue < 1024 || localPortValue > 65535) throw new IllegalArgumentException("SOCKS port must be 1024–65535");

                profile.name = name.getText().toString().trim();
                if (profile.name.isEmpty()) profile.name = hostValue;
                profile.host = hostValue;
                profile.username = userValue;
                profile.sshPort = sshPortValue;
                profile.localPort = localPortValue;

                String pass = passphrase.getText().toString();
                if (pendingKey != null) {
                    profile.encryptedKey = KeyVault.encrypt(pendingKey);
                    profile.encryptedPassphrase = pass.isEmpty() ? "" : KeyVault.encrypt(pass.getBytes(StandardCharsets.UTF_8));
                } else if (!pass.isEmpty()) {
                    profile.encryptedPassphrase = KeyVault.encrypt(pass.getBytes(StandardCharsets.UTF_8));
                }

                if (profile.encryptedKey == null || profile.encryptedKey.isEmpty()) {
                    throw new IllegalArgumentException("Choose an SSH private key");
                }
                ProfileStore.save(this, profile);
                pendingKey = null;
                dialog.dismiss();
                renderProfiles();
            } catch (Exception e) {
                Toast.makeText(this, e.getMessage() == null ? "Could not save profile" : e.getMessage(), Toast.LENGTH_LONG).show();
            }
        }));
        dialog.show();
    }

    private Profile copy(Profile source) {
        Profile p = new Profile(source.name, source.host, source.sshPort, source.username, source.localPort);
        p.id = source.id;
        p.encryptedKey = source.encryptedKey;
        p.encryptedPassphrase = source.encryptedPassphrase;
        p.hostFingerprint = source.hostFingerprint;
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
            pendingKey = output.toByteArray();
            pendingKeyName = uri.getLastPathSegment() == null ? "selected key" : uri.getLastPathSegment();
            Toast.makeText(this, "Private key selected: " + pendingKeyName, Toast.LENGTH_SHORT).show();
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
