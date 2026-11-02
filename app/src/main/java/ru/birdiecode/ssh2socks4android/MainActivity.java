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
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.FrameLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.bottomnavigation.BottomNavigationView;

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
    private LinearLayout keyList;
    private FrameLayout contentHost;
    private BottomNavigationView bottomNavigation;
    private TextView overallStatus;
    private byte[] pendingVaultKey;
    private String pendingVaultKeyName = "";
    private String promptedFingerprint = "";
    private String promptedPasswordRequest = "";

    private final Runnable poll = new Runnable() {
        @Override public void run() {
            refreshStatuses();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQUEST_NOTIFICATIONS);
        }

        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(16), dp(16), dp(16), 0);

        TextView title = text("SSH2SOCKS", 26, 0xFF152033, true);
        page.addView(title);
        TextView subtitle = text("SSH-туннели и локальный SOCKS5", 14, 0xFF65728A, false);
        page.addView(subtitle);

        overallStatus = text("Отключено", 14, 0xFF33415C, true);
        LinearLayout.LayoutParams statusParams = params(-1, -2);
        statusParams.topMargin = dp(12);
        page.addView(overallStatus, statusParams);

        contentHost = new FrameLayout(this);
        LinearLayout.LayoutParams contentParams = new LinearLayout.LayoutParams(-1, 0, 1f);
        contentParams.topMargin = dp(8);
        page.addView(contentHost, contentParams);

        LinearLayout hostsPage = new LinearLayout(this);
        hostsPage.setOrientation(LinearLayout.VERTICAL);
        Button add = new Button(this);
        add.setText("Добавить хост");
        add.setOnClickListener(v -> showEditor(null));
        hostsPage.addView(add);
        ScrollView hostsScroll = new ScrollView(this);
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        hostsScroll.addView(list);
        hostsPage.addView(hostsScroll, new LinearLayout.LayoutParams(-1, 0, 1f));
        TextView help = text("SOCKS5 доступен на этом устройстве: 127.0.0.1:<порт>", 12, 0xFF65728A, false);
        hostsPage.addView(help);
        contentHost.addView(hostsPage);

        LinearLayout keysPage = new LinearLayout(this);
        keysPage.setOrientation(LinearLayout.VERTICAL);
        TextView keyHint = text("Общее хранилище SSH-ключей. Ключи предлагаются каждому узлу цепочки.", 13, 0xFF65728A, false);
        keysPage.addView(keyHint);
        Button importKey = new Button(this);
        importKey.setText("Импортировать приватный ключ");
        importKey.setOnClickListener(v -> launchKeyPicker());
        keysPage.addView(importKey);
        ScrollView keysScroll = new ScrollView(this);
        keyList = new LinearLayout(this);
        keyList.setOrientation(LinearLayout.VERTICAL);
        keysScroll.addView(keyList);
        keysPage.addView(keysScroll, new LinearLayout.LayoutParams(-1, 0, 1f));
        contentHost.addView(keysPage);
        keysPage.setVisibility(View.GONE);

        bottomNavigation = new BottomNavigationView(this);
        bottomNavigation.getMenu().add(0, 1, 0, "Хосты").setIcon(android.R.drawable.ic_menu_agenda);
        bottomNavigation.getMenu().add(0, 2, 1, "Ключи").setIcon(android.R.drawable.ic_lock_lock);
        bottomNavigation.setLabelVisibilityMode(BottomNavigationView.LABEL_VISIBILITY_LABELED);
        bottomNavigation.setOnItemSelectedListener(item -> {
            switchTab(item.getItemId());
            return true;
        });
        page.addView(bottomNavigation, params(-1, -2));

        setContentView(page);
        renderProfiles();
        renderKeyList();
    }

    private void switchTab(int tabId) {
        if (contentHost == null || contentHost.getChildCount() < 2) return;
        contentHost.getChildAt(0).setVisibility(tabId == 1 ? View.VISIBLE : View.GONE);
        contentHost.getChildAt(1).setVisibility(tabId == 2 ? View.VISIBLE : View.GONE);
        if (tabId == 2) renderKeyList();
    }

    private void launchKeyPicker() {
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("*/*");
        startActivityForResult(picker, REQUEST_KEY);
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
            card.setBackgroundColor(resolveColor(com.google.android.material.R.attr.colorSurface, 0xFFFFFFFF));
            card.setPadding(dp(16), dp(14), dp(16), dp(12));
            LinearLayout.LayoutParams cardParams = params(-1, -2);
            cardParams.bottomMargin = dp(10);
            list.addView(card, cardParams);

            TextView name = text(profile.name.isEmpty() ? profile.host : profile.name, 18, 0xFF152033, true);
            card.addView(name);
            Profile jump = profile.jumpProfileId == null || profile.jumpProfileId.isEmpty()
                    ? null : ProfileStore.get(this, profile.jumpProfileId);
            String route = jump == null ? "" : "  ·  через " + jump.name;
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
            overallStatus.setText("Подключено · SOCKS5 127.0.0.1:" + (active == null ? "" : active.localPort));
            overallStatus.setTextColor(0xFF167447);
        } else if ("CONNECTING".equals(status)) {
            overallStatus.setText("Подключение…");
            overallStatus.setTextColor(0xFF8A5A00);
        } else if ("NEEDS_TRUST".equals(status)) {
            overallStatus.setText("Подтвердите SSH fingerprint");
            overallStatus.setTextColor(0xFF8A5A00);
            askToTrust(profileId, detail);
        } else if ("NEEDS_PASSWORD".equals(status)) {
            overallStatus.setText("Требуется пароль SSH");
            overallStatus.setTextColor(0xFF8A5A00);
            askForPassword(profileId, detail);
        } else if ("ERROR".equals(status)) {
            overallStatus.setText("Ошибка подключения");
            overallStatus.setTextColor(0xFFB42318);
        } else {
            overallStatus.setText("Отключено");
            overallStatus.setTextColor(resolveColor(com.google.android.material.R.attr.colorOnSurface, 0xFF33415C));
        }

        for (String id : rowStatuses.keySet()) {
            TextView row = rowStatuses.get(id);
            Button action = rowActions.get(id);
            if (row == null || action == null) continue;
            if (!id.equals(profileId)) {
                row.setText("Отключено");
                action.setText("Подключить");
            } else {
                if ("ERROR".equals(status)) row.setText("Ошибка · нажмите для подробностей");
                else if ("CONNECTED".equals(status)) row.setText("Подключено · " + detail);
                else if ("CONNECTING".equals(status)) row.setText("Подключение…");
                else if ("NEEDS_TRUST".equals(status)) row.setText("Ожидает подтверждения fingerprint");
                else if ("NEEDS_PASSWORD".equals(status)) row.setText("Ожидает пароль для узла цепочки");
                else row.setText("Отключено");
                row.setOnClickListener(v -> {
                    if ("ERROR".equals(ProfileStore.status(this))
                            && id.equals(ProfileStore.statusProfile(this))) {
                        new AlertDialog.Builder(this).setTitle("Ошибка подключения")
                                .setMessage(ProfileStore.statusDetail(this))
                                .setPositiveButton("Закрыть", null).setNeutralButton("Подробности", (d, w) ->
                                        new AlertDialog.Builder(this).setTitle("Техническая информация")
                                                .setMessage(ProfileStore.statusDetail(this))
                                                .setPositiveButton("Закрыть", null).show()).show();
                    }
                });
                boolean running = "CONNECTED".equals(status) || "CONNECTING".equals(status) || "NEEDS_TRUST".equals(status);
                action.setText(running ? "Отключить" : "Подключить");
            }
        }
    }

    private void askToTrust(String profileId, String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty() || fingerprint.equals(promptedFingerprint)) return;
        promptedFingerprint = fingerprint;
        Profile profile = ProfileStore.get(this, profileId);
        if (profile == null) return;
        String[] trustParts = fingerprint.split(":", 3);
        Profile node = profile;
        String shownFingerprint = fingerprint;
        if (trustParts.length == 3 && "NODE".equals(trustParts[0])) {
            Profile resolved = ProfileStore.get(this, trustParts[1]);
            if (resolved != null) node = resolved;
            shownFingerprint = trustParts[2];
        } else if ((fingerprint.startsWith("JUMP:") || fingerprint.startsWith("TARGET:"))
                && fingerprint.indexOf(':') >= 0) {
            shownFingerprint = fingerprint.substring(fingerprint.indexOf(':') + 1);
        }
        String server = node.username + "@" + node.host + ":" + node.sshPort;
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

    private void askForPassword(String targetId, String request) {
        if (request == null || !request.startsWith("NODE:") || request.equals(promptedPasswordRequest)) return;
        String nodeId = request.substring("NODE:".length());
        Profile node = ProfileStore.get(this, nodeId);
        if (node == null) return;
        promptedPasswordRequest = request;
        EditText password = input("SSH-пароль для " + node.username + "@" + node.host, "",
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        new AlertDialog.Builder(this)
                .setTitle("Требуется пароль SSH")
                .setMessage("Пароль запрашивается для " + node.username + "@" + node.host + ":" + node.sshPort
                        + ". Он будет сохранён только после успешной парольной авторизации.")
                .setView(password)
                .setNegativeButton("Отмена", (d, w) -> {
                    promptedPasswordRequest = "";
                    startTunnelAction(SshTunnelService.ACTION_STOP, targetId);
                })
                .setPositiveButton("Подключиться", (d, w) -> {
                    promptedPasswordRequest = "";
                    String value = password.getText().toString();
                    if (value.isEmpty()) {
                        Toast.makeText(this, "Введите пароль или отмените подключение", Toast.LENGTH_LONG).show();
                        startTunnelAction(SshTunnelService.ACTION_STOP, targetId);
                        return;
                    }
                    Intent intent = new Intent(this, SshTunnelService.class);
                    intent.setAction(SshTunnelService.ACTION_PASSWORD);
                    intent.putExtra(SshTunnelService.EXTRA_PROFILE_ID, targetId);
                    intent.putExtra(SshTunnelService.EXTRA_NODE_ID, nodeId);
                    intent.putExtra(SshTunnelService.EXTRA_PASSWORD, value);
                    try {
                        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent);
                        else startService(intent);
                    } catch (Exception e) {
                        Toast.makeText(this, "Не удалось продолжить подключение", Toast.LENGTH_LONG).show();
                    }
                }).show();
    }

    private void toggle(Profile profile) {
        String status = ProfileStore.status(this);
        String activeId = ProfileStore.statusProfile(this);
        if (profile.id.equals(activeId) && ("CONNECTED".equals(status)
                || "CONNECTING".equals(status) || "NEEDS_TRUST".equals(status) || "NEEDS_PASSWORD".equals(status))) {
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
        List<Profile> dependents = ProfileStore.dependents(this, profile.id);
        StringBuilder message = new StringBuilder("Зашифрованные данные и профиль будут удалены.");
        if (!dependents.isEmpty()) {
            message.append("\n\nЭтот узел используется в маршрутах:");
            for (Profile dependent : dependents) {
                message.append("\n• ").append(dependent.name);
            }
            message.append("\n\nУ этих профилей маршрут будет переключён на прямое подключение.");
        }
        new AlertDialog.Builder(this)
                .setTitle("Удалить «" + profile.name + "»?")
                .setMessage(message.toString())
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Удалить", (dialog, which) -> {
                    if (profile.id.equals(ProfileStore.statusProfile(this))) {
                        startTunnelAction(SshTunnelService.ACTION_STOP, profile.id);
                    }
                    ProfileStore.delete(this, profile.id);
                    renderProfiles();
                })
                .show();
    }

    private void showEditor(Profile existing) {
        final Profile profile = existing == null ? new Profile("", "", 22, "", 1080) : copy(existing);
        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(16), dp(8), dp(16), dp(8));

        EditText name = input("Название", profile.name, InputType.TYPE_CLASS_TEXT);
        EditText host = input("Адрес сервера", profile.host,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        EditText sshPort = input("SSH-порт", String.valueOf(profile.sshPort), InputType.TYPE_CLASS_NUMBER);
        EditText username = input("Имя пользователя", profile.username, InputType.TYPE_CLASS_TEXT);
        EditText localPort = input("Локальный SOCKS5-порт", String.valueOf(profile.localPort), InputType.TYPE_CLASS_NUMBER);
        EditText password = input("Пароль SSH (необязательно)", "",
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setHint(profile.encryptedPassword == null || profile.encryptedPassword.isEmpty()
                ? "Пароль SSH (необязательно)" : "Сохранённый пароль есть · пустое поле оставит его");
        Button clearPassword = new Button(this);
        clearPassword.setText("Удалить сохранённый пароль");
        final boolean[] removePassword = {false};
        clearPassword.setOnClickListener(v -> {
            removePassword[0] = true;
            password.setText("");
            password.setHint("Пароль будет удалён при сохранении");
        });
        form.addView(name);
        form.addView(host);
        form.addView(sshPort);
        form.addView(username);
        form.addView(password);
        form.addView(clearPassword);

        TextView routeTitle = text("Подключаться через", 16, 0xFF152033, true);
        LinearLayout.LayoutParams routeTitleParams = params(-1, -2);
        routeTitleParams.topMargin = dp(12);
        form.addView(routeTitle, routeTitleParams);

        ArrayList<Profile> options = new ArrayList<>();
        options.add(null);
        String selectedId = profile.jumpProfileId == null ? "" : profile.jumpProfileId;
        List<Profile> saved = ProfileStore.all(this);
        for (Profile candidate : saved) {
            if (candidate.id.equals(profile.id)) continue;
            if (selectedId.isEmpty() && profile.jumpHost != null
                    && candidate.host.equalsIgnoreCase(profile.jumpHost)
                    && candidate.sshPort == profile.jumpPort
                    && candidate.username.equals(profile.jumpUsername)) selectedId = candidate.id;
            options.add(candidate);
        }
        ArrayList<String> labels = new ArrayList<>();
        labels.add("Напрямую");
        int selectedIndex = 0;
        for (int i = 1; i < options.size(); i++) {
            Profile candidate = options.get(i);
            labels.add(candidate.name + " · " + candidate.username + "@" + candidate.host);
            if (candidate.id.equals(selectedId)) selectedIndex = i;
        }
        Spinner route = new Spinner(this);
        route.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, labels));
        route.setSelection(selectedIndex);
        form.addView(route);
        form.addView(localPort);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(form);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(existing == null ? "Добавить хост" : "Изменить хост")
                .setView(scroll).setNegativeButton("Отмена", null)
                .setPositiveButton("Сохранить", null).create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                String hostValue = host.getText().toString().trim();
                String userValue = username.getText().toString().trim();
                int sshPortValue = parsePort(sshPort.getText().toString(), "SSH-порт");
                int socksPortValue = parsePort(localPort.getText().toString(), "SOCKS5-порт");
                if (hostValue.isEmpty() || userValue.isEmpty()) {
                    throw new IllegalArgumentException("Укажите адрес сервера и имя пользователя");
                }
                if (socksPortValue < 1024) throw new IllegalArgumentException("Локальный порт должен быть от 1024 до 65535");

                Profile jump = options.get(route.getSelectedItemPosition());
                String jumpId = jump == null ? "" : jump.id;
                if (!jumpId.isEmpty() && wouldCreateCycle(profile.id, jumpId)) {
                    throw new IllegalArgumentException("Эта настройка создаёт циклический ProxyJump");
                }
                profile.name = name.getText().toString().trim();
                if (profile.name.isEmpty()) profile.name = hostValue;
                profile.host = hostValue;
                profile.username = userValue;
                profile.sshPort = sshPortValue;
                profile.localPort = socksPortValue;
                profile.jumpProfileId = jumpId;
                profile.jumpHost = "";
                profile.jumpUsername = "";
                profile.encryptedJumpPassword = "";
                profile.jumpKeyId = "";
                profile.jumpFingerprint = "";

                if (removePassword[0]) profile.encryptedPassword = "";
                String enteredPassword = password.getText().toString();
                if (!enteredPassword.isEmpty()) {
                    profile.encryptedPassword = KeyVault.encrypt(enteredPassword.getBytes(StandardCharsets.UTF_8));
                }

                ProfileStore.save(this, profile);
                dialog.dismiss();
                renderProfiles();
            } catch (Exception e) {
                Toast.makeText(this, e.getMessage() == null ? "Не удалось сохранить хост" : e.getMessage(),
                        Toast.LENGTH_LONG).show();
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
        if (bottomNavigation != null) bottomNavigation.setSelectedItemId(2);
        switchTab(2);
    }

    private void renderKeyList() {
        if (keyList == null) return;
        keyList.removeAllViews();
        List<SshKey> keys = SshKeyStore.all(this);
        if (keys.isEmpty()) {
            TextView empty = text("Нет импортированных ключей. Можно подключаться по паролю.", 14, 0xFF65728A, false);
            empty.setPadding(dp(8), dp(24), dp(8), dp(24));
            keyList.addView(empty);
            return;
        }
        for (SshKey key : keys) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(dp(12), dp(10), dp(12), dp(10));
            TextView label = text(key.name, 16, 0xFF152033, true);
            row.addView(label);
            LinearLayout actions = new LinearLayout(this);
            actions.setOrientation(LinearLayout.HORIZONTAL);
            Button rename = new Button(this);
            rename.setText("Переименовать");
            rename.setOnClickListener(v -> {
                SshKey current = SshKeyStore.get(this, key.id);
                if (current == null) return;
                EditText field = input("Название ключа", current.name, InputType.TYPE_CLASS_TEXT);
                new AlertDialog.Builder(this).setTitle("Переименовать ключ")
                        .setView(field).setNegativeButton("Отмена", null)
                        .setPositiveButton("Сохранить", (d, w) -> {
                            String value = field.getText().toString().trim();
                            if (!value.isEmpty()) {
                                current.name = value;
                                SshKeyStore.save(this, current);
                                renderKeyList();
                            }
                        }).show();
            });
            Button delete = new Button(this);
            delete.setText("Удалить");
            delete.setOnClickListener(v -> new AlertDialog.Builder(this)
                    .setTitle("Удалить ключ?")
                    .setMessage("Ключ будет удалён из общего хранилища.")
                    .setNegativeButton("Отмена", null)
                    .setPositiveButton("Удалить", (d, w) -> {
                        SshKeyStore.delete(this, key.id);
                        renderKeyList();
                    }).show());
            actions.addView(rename, new LinearLayout.LayoutParams(0, -2, 1f));
            actions.addView(delete, new LinearLayout.LayoutParams(0, -2, 1f));
            row.addView(actions);
            keyList.addView(row);
            View divider = new View(this);
            divider.setBackgroundColor(resolveColor(com.google.android.material.R.attr.colorOutlineVariant, 0xFFE0E3E8));
            keyList.addView(divider, params(-1, dp(1)));
        }
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
        p.jumpProfileId = source.jumpProfileId;
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

    private int resolveColor(int attribute, int fallback) {
        TypedValue value = new TypedValue();
        return getTheme().resolveAttribute(attribute, value, true) ? value.data : fallback;
    }

    private TextView text(String value, int sizeSp, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sizeSp);
        int finalColor = color;
        if (color == 0xFF65728A) {
            finalColor = resolveColor(com.google.android.material.R.attr.colorOnSurfaceVariant, color);
        } else if (color == 0xFF152033 || color == 0xFF33415C) {
            finalColor = resolveColor(com.google.android.material.R.attr.colorOnSurface, color);
        }
        view.setTextColor(finalColor);
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
