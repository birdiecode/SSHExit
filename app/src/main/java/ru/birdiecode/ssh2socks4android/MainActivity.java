package ru.birdiecode.ssh2socks4android;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Typeface;
import android.content.res.Configuration;
import android.content.res.ColorStateList;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.ScrollView;
import android.widget.FrameLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

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
    private final Map<String, MaterialButton> rowActions = new HashMap<>();
    private final Map<String, TextView> rowFingerprints = new HashMap<>();
    private final Map<String, View> rowErrorPanels = new HashMap<>();
    private final Map<String, TextView> rowErrorSummaries = new HashMap<>();
    private final Map<String, TextView> rowTechnicalDetails = new HashMap<>();

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
        page.setPadding(dp(20), dp(12), dp(20), 0);
        ViewCompat.setOnApplyWindowInsetsListener(page, (view, windowInsets) -> {
            Insets systemBars = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars());
            view.setPadding(dp(20), dp(12) + systemBars.top, dp(20), systemBars.bottom);
            return windowInsets;
        });
        page.setBackgroundColor(resolveColor(com.google.android.material.R.attr.colorSurface, 0xFFF7F8FC));

        TextView title = text("SSH2SOCKS", 23, 0xFF152033, true);
        page.addView(title);
        TextView subtitle = text("SSH-туннели · локальный SOCKS5", 14, 0xFF65728A, false);
        LinearLayout.LayoutParams subtitleParams = params(-1, -2);
        subtitleParams.topMargin = dp(2);
        page.addView(subtitle, subtitleParams);

        overallStatus = text("Отключено", 14, 0xFF33415C, true);
        overallStatus.setPadding(dp(14), dp(12), dp(14), dp(12));
        MaterialCardView statusCard = surfaceCard();
        statusCard.setCardElevation(0);
        statusCard.setStrokeWidth(0);
        LinearLayout.LayoutParams statusCardParams = params(-1, -2);
        statusCardParams.topMargin = dp(14);
        page.addView(statusCard, statusCardParams);
        statusCard.addView(overallStatus);

        contentHost = new FrameLayout(this);
        LinearLayout.LayoutParams contentParams = new LinearLayout.LayoutParams(-1, 0, 1f);
        contentParams.topMargin = dp(12);
        page.addView(contentHost, contentParams);

        LinearLayout hostsPage = new LinearLayout(this);
        hostsPage.setOrientation(LinearLayout.VERTICAL);
        MaterialButton add = makeButton("Добавить хост", true);
        LinearLayout.LayoutParams addParams = params(-1, -2);
        addParams.bottomMargin = dp(10);
        hostsPage.addView(add, addParams);
        add.setOnClickListener(v -> showEditor(null));

        ScrollView hostsScroll = new ScrollView(this);
        hostsScroll.setClipToPadding(false);
        hostsScroll.setFillViewport(false);
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        list.setPadding(0, dp(2), 0, dp(12));
        hostsScroll.addView(list);
        hostsPage.addView(hostsScroll, new LinearLayout.LayoutParams(-1, 0, 1f));
        TextView help = text("Прокси доступен на устройстве по адресу 127.0.0.1:<порт>", 12, 0xFF65728A, false);
        LinearLayout.LayoutParams helpParams = params(-1, -2);
        helpParams.topMargin = dp(4);
        helpParams.bottomMargin = dp(6);
        hostsPage.addView(help, helpParams);
        contentHost.addView(hostsPage);

        LinearLayout keysPage = new LinearLayout(this);
        keysPage.setOrientation(LinearLayout.VERTICAL);
        TextView keyHint = text("Общее хранилище SSH-ключей. Ключи проверяются для каждого узла цепочки.",
                13, 0xFF65728A, false);
        keyHint.setPadding(dp(2), dp(2), dp(2), dp(12));
        keysPage.addView(keyHint);
        MaterialButton importKey = makeButton("Импортировать приватный ключ", true);
        keysPage.addView(importKey, params(-1, -2));
        importKey.setOnClickListener(v -> launchKeyPicker());
        ScrollView keysScroll = new ScrollView(this);
        keysScroll.setClipToPadding(false);
        keyList = new LinearLayout(this);
        keyList.setOrientation(LinearLayout.VERTICAL);
        keyList.setPadding(0, dp(12), 0, dp(12));
        keysScroll.addView(keyList);
        keysPage.addView(keysScroll, new LinearLayout.LayoutParams(-1, 0, 1f));
        contentHost.addView(keysPage);
        keysPage.setVisibility(View.GONE);

        bottomNavigation = new BottomNavigationView(this);
        bottomNavigation.getMenu().add(0, 1, 0, "Хосты").setIcon(R.drawable.ic_hosts);
        bottomNavigation.getMenu().add(0, 2, 1, "Ключи").setIcon(R.drawable.ic_keys);
        bottomNavigation.setLabelVisibilityMode(BottomNavigationView.LABEL_VISIBILITY_LABELED);
        bottomNavigation.setBackgroundColor(resolveColor(com.google.android.material.R.attr.colorSurface, 0xFFF7F8FC));
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
        rowFingerprints.clear();
        rowErrorPanels.clear();
        rowErrorSummaries.clear();
        rowTechnicalDetails.clear();

        List<Profile> profiles = ProfileStore.all(this);
        if (profiles.isEmpty()) {
            MaterialCardView emptyCard = surfaceCard();
            LinearLayout emptyContent = new LinearLayout(this);
            emptyContent.setOrientation(LinearLayout.VERTICAL);
            emptyContent.setGravity(Gravity.CENTER);
            emptyContent.setPadding(dp(20), dp(28), dp(20), dp(28));
            TextView emptyTitle = text("Пока нет хостов", 18, 0xFF152033, true);
            emptyTitle.setGravity(Gravity.CENTER);
            emptyContent.addView(emptyTitle);
            TextView empty = text("Добавьте SSH-сервер и выберите подключение напрямую или через ProxyJump.",
                    14, 0xFF65728A, false);
            empty.setGravity(Gravity.CENTER);
            LinearLayout.LayoutParams emptyParams = params(-1, -2);
            emptyParams.topMargin = dp(8);
            emptyContent.addView(empty, emptyParams);
            emptyCard.addView(emptyContent);
            list.addView(emptyCard, params(-1, -2));
            return;
        }

        for (Profile profile : profiles) {
            MaterialCardView card = surfaceCard();
            card.setContentPadding(dp(16), dp(14), dp(16), dp(14));
            LinearLayout.LayoutParams cardParams = params(-1, -2);
            cardParams.bottomMargin = dp(12);
            list.addView(card, cardParams);

            LinearLayout content = new LinearLayout(this);
            content.setOrientation(LinearLayout.VERTICAL);
            card.addView(content);

            LinearLayout titleRow = new LinearLayout(this);
            titleRow.setGravity(Gravity.CENTER_VERTICAL);
            content.addView(titleRow);
            TextView name = text(profile.name.isEmpty() ? profile.host : profile.name, 18, 0xFF152033, true);
            titleRow.addView(name, new LinearLayout.LayoutParams(0, -2, 1f));
            TextView state = statusChip();
            LinearLayout.LayoutParams chipParams = params(-2, -2);
            chipParams.leftMargin = dp(8);
            titleRow.addView(state, chipParams);
            rowStatuses.put(profile.id, state);

            MaterialButton more = overflowButton();
            LinearLayout.LayoutParams moreParams = params(dp(44), dp(44));
            moreParams.leftMargin = dp(4);
            titleRow.addView(more, moreParams);
            more.setOnClickListener(v -> showProfileActions(profile, more));

            TextView endpoint = text(profile.username + "@" + formatHostPort(profile.host, profile.sshPort),
                    14, 0xFF33415C, false);
            LinearLayout.LayoutParams endpointParams = params(-1, -2);
            endpointParams.topMargin = dp(8);
            content.addView(endpoint, endpointParams);

            TextView route = text("", 13, 0xFF65728A, false);
            Profile jump = profile.jumpProfileId == null || profile.jumpProfileId.isEmpty()
                    ? null : ProfileStore.get(this, profile.jumpProfileId);
            if (jump != null) {
                route.setText("Маршрут через " + (jump.name.isEmpty() ? jump.host : jump.name));
                LinearLayout.LayoutParams routeParams = params(-1, -2);
                routeParams.topMargin = dp(3);
                content.addView(route, routeParams);
            }

            LinearLayout socksRow = new LinearLayout(this);
            socksRow.setGravity(Gravity.CENTER_VERTICAL);
            LinearLayout.LayoutParams socksParams = params(-1, -2);
            socksParams.topMargin = dp(9);
            content.addView(socksRow, socksParams);
            TextView socksLabel = text("SOCKS5", 12, 0xFF65728A, true);
            socksRow.addView(socksLabel);
            TextView socksPort = text("127.0.0.1:" + profile.localPort, 13, 0xFF2457D6, true);
            LinearLayout.LayoutParams socksPortParams = params(-2, -2);
            socksPortParams.leftMargin = dp(8);
            socksRow.addView(socksPort, socksPortParams);

            TextView fingerprint = text("", 12, 0xFF65728A, false);
            fingerprint.setTextIsSelectable(true);
            fingerprint.setPadding(dp(12), dp(9), dp(12), dp(9));
            GradientDrawable fingerprintBackground = new GradientDrawable();
            fingerprintBackground.setColor(resolveColor(com.google.android.material.R.attr.colorSurface,
                    0xFFF1F4F8));
            fingerprintBackground.setCornerRadius(dp(12));
            fingerprint.setBackground(fingerprintBackground);
            LinearLayout.LayoutParams fingerprintParams = params(-1, -2);
            fingerprintParams.topMargin = dp(10);
            content.addView(fingerprint, fingerprintParams);
            rowFingerprints.put(profile.id, fingerprint);
            updateFingerprintStatus(fingerprint, profile);

            LinearLayout errorPanel = new LinearLayout(this);
            errorPanel.setOrientation(LinearLayout.VERTICAL);
            errorPanel.setPadding(dp(12), dp(10), dp(12), dp(10));
            GradientDrawable errorBackground = new GradientDrawable();
            errorBackground.setColor(0x1FB42318);
            errorBackground.setCornerRadius(dp(12));
            errorPanel.setBackground(errorBackground);
            LinearLayout.LayoutParams errorPanelParams = params(-1, -2);
            errorPanelParams.topMargin = dp(10);
            content.addView(errorPanel, errorPanelParams);
            TextView errorSummary = text("", 13, 0xFFB42318, true);
            errorPanel.addView(errorSummary);
            TextView technicalToggle = text("Технические подробности  ▾", 12, 0xFF2457D6, true);
            LinearLayout.LayoutParams technicalToggleParams = params(-1, -2);
            technicalToggleParams.topMargin = dp(6);
            errorPanel.addView(technicalToggle, technicalToggleParams);
            TextView technicalDetails = text("", 12, 0xFF65728A, false);
            technicalDetails.setTextIsSelectable(true);
            technicalDetails.setVisibility(View.GONE);
            LinearLayout.LayoutParams technicalDetailsParams = params(-1, -2);
            technicalDetailsParams.topMargin = dp(6);
            errorPanel.addView(technicalDetails, technicalDetailsParams);
            technicalToggle.setOnClickListener(v -> {
                boolean show = technicalDetails.getVisibility() != View.VISIBLE;
                technicalDetails.setVisibility(show ? View.VISIBLE : View.GONE);
                technicalToggle.setText(show ? "Скрыть подробности  ▴" : "Технические подробности  ▾");
            });
            errorPanel.setVisibility(View.GONE);
            rowErrorPanels.put(profile.id, errorPanel);
            rowErrorSummaries.put(profile.id, errorSummary);
            rowTechnicalDetails.put(profile.id, technicalDetails);

            MaterialButton action = makeButton("Подключить", true);
            action.setOnClickListener(v -> toggle(profile));
            LinearLayout.LayoutParams actionParams = params(-1, dp(46));
            actionParams.topMargin = dp(12);
            content.addView(action, actionParams);
            rowActions.put(profile.id, action);

            LinearLayout secondaryActions = new LinearLayout(this);
            secondaryActions.setOrientation(LinearLayout.HORIZONTAL);
            LinearLayout.LayoutParams secondaryParams = params(-1, -2);
            secondaryParams.topMargin = dp(6);
            content.addView(secondaryActions, secondaryParams);

            MaterialButton edit = makeButton("Изменить", false);
            edit.setOnClickListener(v -> showEditor(profile));
            secondaryActions.addView(edit, new LinearLayout.LayoutParams(0, dp(46), 1f));

            MaterialButton delete = makeButton("Удалить", false);
            delete.setOnClickListener(v -> confirmDelete(profile));
            LinearLayout.LayoutParams deleteParams = new LinearLayout.LayoutParams(0, dp(46), 1f);
            deleteParams.leftMargin = dp(8);
            secondaryActions.addView(delete, deleteParams);

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
            overallStatus.setText("Подключено  ·  SOCKS5 127.0.0.1:" + (active == null ? "" : active.localPort));
            overallStatus.setTextColor(resolveColor(android.R.attr.colorAccent, 0xFF2457D6));
        } else if ("CONNECTING".equals(status)) {
            overallStatus.setText("Подключение…");
            overallStatus.setTextColor(resolveColor(com.google.android.material.R.attr.colorOnSurface, 0xFF33415C));
        } else if ("NEEDS_TRUST".equals(status)) {
            overallStatus.setText("Нужно подтвердить fingerprint сервера");
            overallStatus.setTextColor(resolveColor(android.R.attr.colorAccent, 0xFF2457D6));
            askToTrust(profileId, detail);
        } else if ("NEEDS_PASSWORD".equals(status)) {
            overallStatus.setText("Требуется пароль SSH");
            overallStatus.setTextColor(resolveColor(com.google.android.material.R.attr.colorOnSurface, 0xFF33415C));
            askForPassword(profileId, detail);
        } else if ("ERROR".equals(status)) {
            overallStatus.setText("Не удалось подключиться  ·  описание ошибки в карточке хоста");
            overallStatus.setTextColor(0xFFB42318);
        } else {
            overallStatus.setText("Нет активного подключения");
            overallStatus.setTextColor(resolveColor(com.google.android.material.R.attr.colorOnSurfaceVariant, 0xFF65728A));
        }

        for (String id : rowStatuses.keySet()) {
            TextView row = rowStatuses.get(id);
            MaterialButton action = rowActions.get(id);
            Profile rowProfile = ProfileStore.get(this, id);
            TextView fingerprint = rowFingerprints.get(id);
            if (rowProfile != null && fingerprint != null) updateFingerprintStatus(fingerprint, rowProfile);
            View errorPanel = rowErrorPanels.get(id);
            TextView errorSummary = rowErrorSummaries.get(id);
            TextView technicalDetails = rowTechnicalDetails.get(id);
            boolean showError = id.equals(profileId) && "ERROR".equals(status);
            if (errorPanel != null) errorPanel.setVisibility(showError ? View.VISIBLE : View.GONE);
            if (showError) {
                String rawError = detail == null || detail.trim().isEmpty() ? "Подробности отсутствуют." : detail;
                if (errorSummary != null) errorSummary.setText(friendlyConnectionError(rawError));
                if (technicalDetails != null) technicalDetails.setText(rawError);
            }
            if (row == null || action == null) continue;
            if (!id.equals(profileId)) {
                boolean hasFingerprintError = rowProfile != null && rowProfile.observedFingerprint != null
                        && !rowProfile.observedFingerprint.isEmpty();
                setStatusChip(row, hasFingerprintError ? "Fingerprint не совпал" : "Отключено",
                        hasFingerprintError ? "ERROR" : "IDLE");
                action.setText("Подключить");
                styleButton(action, true);
            } else {
                if ("ERROR".equals(status)) {
                    boolean fingerprintError = rowProfile != null && rowProfile.observedFingerprint != null
                            && !rowProfile.observedFingerprint.isEmpty();
                    setStatusChip(row, fingerprintError ? "Fingerprint не совпал" : "Ошибка",
                            "ERROR");
                    row.setOnClickListener(null);
                } else if ("CONNECTED".equals(status)) {
                    setStatusChip(row, "Подключено", "CONNECTED");
                } else if ("CONNECTING".equals(status)) {
                    setStatusChip(row, "Подключение…", "CONNECTING");
                } else if ("NEEDS_TRUST".equals(status)) {
                    setStatusChip(row, "Ожидает проверки", "CONNECTING");
                } else if ("NEEDS_PASSWORD".equals(status)) {
                    setStatusChip(row, "Ожидает пароль", "CONNECTING");
                } else {
                    setStatusChip(row, "Отключено", "IDLE");
                }
                boolean running = "CONNECTED".equals(status) || "CONNECTING".equals(status)
                        || "NEEDS_TRUST".equals(status) || "NEEDS_PASSWORD".equals(status);
                action.setText(running ? "Отключить" : "Подключить");
                styleButton(action, !running);
            }
        }
    }

    private String friendlyConnectionError(String rawError) {
        String lower = rawError.toLowerCase(java.util.Locale.ROOT);
        if (lower.contains("channel is not opened")
                || lower.contains("could not open a tcp forwarding channel")) {
            return "SSH-сервер не открыл TCP-канал до целевого узла. При ProxyJump проверьте, доступен ли IPv6-адрес с jump-сервера и разрешён ли на нём TCP forwarding.";
        }
        if (lower.contains("fingerprint")) {
            return "Отпечаток ключа сервера не совпал с доверенным. Подключение остановлено для защиты соединения.";
        }
        return "Подключение не установлено. Техническую причину можно раскрыть ниже.";
    }

    private String formatHostPort(String host, int port) {
        String value = host == null ? "" : host.trim();
        if (value.contains(":") && !(value.startsWith("[") && value.endsWith("]"))) {
            value = "[" + value + "]";
        }
        return value + ":" + port;
    }

    private TextView statusChip() {
        TextView chip = text("", 11, 0xFF65728A, true);
        chip.setGravity(Gravity.CENTER);
        chip.setPadding(dp(10), dp(6), dp(10), dp(6));
        GradientDrawable background = new GradientDrawable();
        background.setCornerRadius(dp(20));
        chip.setBackground(background);
        return chip;
    }

    private void setStatusChip(TextView chip, String label, String state) {
        chip.setText(label);
        GradientDrawable background = new GradientDrawable();
        background.setCornerRadius(dp(20));
        boolean dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        if ("CONNECTED".equals(state)) {
            background.setColor(dark ? 0xFF173B2D : 0xFFE7F5EC);
            chip.setTextColor(dark ? 0xFF8DE0AF : 0xFF176B3A);
        } else if ("ERROR".equals(state)) {
            background.setColor(dark ? 0xFF492526 : 0xFFFCEBEC);
            chip.setTextColor(dark ? 0xFFFFB4AB : 0xFFB42318);
        } else if ("CONNECTING".equals(state)) {
            background.setColor(resolveColor(com.google.android.material.R.attr.colorSurface, 0xFFF1F4F8));
            chip.setTextColor(resolveColor(android.R.attr.colorAccent, 0xFF2457D6));
        } else {
            background.setColor(resolveColor(com.google.android.material.R.attr.colorSurface, 0xFFF1F4F8));
            chip.setTextColor(resolveColor(com.google.android.material.R.attr.colorOnSurfaceVariant, 0xFF65728A));
        }
        chip.setBackground(background);
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
                .setTitle("Подтвердите SSH-сервер")
                .setMessage("Сервер: " + server
                        + "\n\nFingerprint:\n" + shownFingerprint
                        + "\n\nСравните значение с fingerprint сервера по доверенному каналу перед подтверждением.")
                .setPositiveButton("Доверять и подключиться", (dialog, which) -> {
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
            Toast.makeText(this, "Не удалось запустить подключение: " + e.getMessage(), Toast.LENGTH_LONG).show();
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

    private void updateFingerprintStatus(TextView view, Profile profile) {
        String trusted = profile.hostFingerprint == null ? "" : profile.hostFingerprint;
        String observed = profile.observedFingerprint == null ? "" : profile.observedFingerprint;
        if (!observed.isEmpty()) {
            view.setText("Проверка fingerprint не пройдена\nДоверенный: " + trusted + "\nПолучен: " + observed);
            view.setTextColor(0xFFB42318);
            return;
        }
        if (!trusted.isEmpty()) {
            view.setText("Доверенный fingerprint\n" + trusted);
            view.setTextColor(resolveColor(com.google.android.material.R.attr.colorOnSurfaceVariant, 0xFF65728A));
            return;
        }
        String pending = ProfileStore.statusDetail(this);
        String nodePrefix = "NODE:" + profile.id + ":";
        if ("NEEDS_TRUST".equals(ProfileStore.status(this)) && pending != null && pending.startsWith(nodePrefix)) {
            view.setText("Fingerprint ожидает подтверждения\n" + pending.substring(nodePrefix.length()));
            view.setTextColor(resolveColor(android.R.attr.colorAccent, 0xFF2457D6));
        } else {
            view.setText("Доверенный fingerprint не задан");
            view.setTextColor(resolveColor(com.google.android.material.R.attr.colorOnSurfaceVariant, 0xFF65728A));
        }
    }

    private void confirmFingerprintReset(Profile profile) {
        new AlertDialog.Builder(this)
                .setTitle("Удалить доверенный fingerprint?")
                .setMessage("При следующем подключении нужно будет сверить fingerprint сервера и подтвердить его заново.")
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Удалить", (dialog, which) -> {
                    Profile stored = ProfileStore.get(this, profile.id);
                    if (stored == null) return;
                    stored.hostFingerprint = "";
                    stored.observedFingerprint = "";
                    ProfileStore.save(this, stored);
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
        MaterialButton clearPassword = new MaterialButton(this);
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
            MaterialCardView emptyCard = surfaceCard();
            TextView empty = text("Нет импортированных ключей. Можно подключаться по паролю.",
                    14, 0xFF65728A, false);
            empty.setPadding(dp(16), dp(20), dp(16), dp(20));
            emptyCard.addView(empty);
            keyList.addView(emptyCard, params(-1, -2));
            return;
        }
        for (SshKey key : keys) {
            MaterialCardView card = surfaceCard();
            card.setCardElevation(0);
            card.setContentPadding(dp(14), dp(12), dp(14), dp(12));
            LinearLayout.LayoutParams cardParams = params(-1, -2);
            cardParams.bottomMargin = dp(10);
            keyList.addView(card, cardParams);

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            card.addView(row);
            LinearLayout heading = new LinearLayout(this);
            heading.setGravity(Gravity.CENTER_VERTICAL);
            row.addView(heading);
            TextView label = text(key.name, 16, 0xFF152033, true);
            label.setMaxLines(2);
            label.setEllipsize(android.text.TextUtils.TruncateAt.END);
            heading.addView(label, new LinearLayout.LayoutParams(0, -2, 1f));
            MaterialButton more = overflowButton();
            heading.addView(more, params(dp(44), dp(44)));
            more.setOnClickListener(v -> showKeyActions(key, more));

            TextView description = text("Приватный ключ · общее хранилище", 12, 0xFF65728A, false);
            LinearLayout.LayoutParams descriptionParams = params(-1, -2);
            descriptionParams.topMargin = dp(2);
            row.addView(description, descriptionParams);
        }
    }

    private MaterialButton overflowButton() {
        MaterialButton button = new MaterialButton(this);
        button.setText("");
        button.setIconResource(android.R.drawable.ic_menu_more);
        button.setIconTint(ColorStateList.valueOf(
                resolveColor(com.google.android.material.R.attr.colorOnSurfaceVariant, 0xFF65728A)));
        button.setContentDescription("Действия");
        button.setMinWidth(dp(44));
        button.setMinimumWidth(dp(44));
        button.setMinimumHeight(dp(44));
        button.setInsetTop(0);
        button.setInsetBottom(0);
        button.setCornerRadius(dp(22));
        button.setElevation(0);
        button.setBackgroundTintList(ColorStateList.valueOf(
                resolveColor(com.google.android.material.R.attr.colorSurface, 0xFFFFFFFF)));
        return button;
    }

    private void showProfileActions(Profile profile, View anchor) {
        PopupMenu menu = new PopupMenu(this, anchor);
        menu.getMenu().add("Изменить").setOnMenuItemClickListener(item -> {
            showEditor(profile);
            return true;
        });
        menu.getMenu().add("Удалить").setOnMenuItemClickListener(item -> {
            confirmDelete(profile);
            return true;
        });
        if (profile.hostFingerprint != null && !profile.hostFingerprint.isEmpty()) {
            menu.getMenu().add("Сбросить fingerprint").setOnMenuItemClickListener(item -> {
                confirmFingerprintReset(profile);
                return true;
            });
        }
        menu.show();
    }

    private void showKeyActions(SshKey key, View anchor) {
        PopupMenu menu = new PopupMenu(this, anchor);
        menu.getMenu().add("Переименовать").setOnMenuItemClickListener(item -> {
            SshKey current = SshKeyStore.get(this, key.id);
            if (current == null) return true;
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
            return true;
        });
        menu.getMenu().add("Удалить").setOnMenuItemClickListener(item -> {
            new AlertDialog.Builder(this)
                    .setTitle("Удалить ключ?")
                    .setMessage("Ключ будет удалён из общего хранилища.")
                    .setNegativeButton("Отмена", null)
                    .setPositiveButton("Удалить", (d, w) -> {
                        SshKeyStore.delete(this, key.id);
                        renderKeyList();
                    }).show();
            return true;
        });
        menu.show();
    }

    private void showSaveKeyDialog() {
        if (pendingVaultKey == null) return;
        EditText name = input("Название ключа", pendingVaultKeyName, InputType.TYPE_CLASS_TEXT);
        EditText passphrase = input("Парольная фраза ключа (если зашифрован)", "", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(20), dp(8), dp(20), dp(4));
        form.addView(name);
        form.addView(passphrase);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Сохранить приватный ключ")
                .setView(form)
                .setNegativeButton("Отмена", (d, w) -> pendingVaultKey = null)
                .setPositiveButton("Сохранить", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            try {
                String keyName = name.getText().toString().trim();
                if (keyName.isEmpty()) keyName = "SSH-ключ";
                String secret = passphrase.getText().toString();
                SshKey key = new SshKey(
                        keyName,
                        KeyVault.encrypt(pendingVaultKey),
                        secret.isEmpty() ? "" : KeyVault.encrypt(secret.getBytes(StandardCharsets.UTF_8)));
                SshKeyStore.save(this, key);
                pendingVaultKey = null;
                dialog.dismiss();
                Toast.makeText(this, "Ключ сохранён в общем хранилище", Toast.LENGTH_SHORT).show();
                showKeyManager();
            } catch (Exception e) {
                Toast.makeText(this, e.getMessage() == null ? "Не удалось сохранить ключ" : e.getMessage(), Toast.LENGTH_LONG).show();
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
            if (input == null) throw new IllegalStateException("Не удалось прочитать выбранный файл");
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
            pendingVaultKey = output.toByteArray();
            String filename = null;
            try (Cursor cursor = getContentResolver().query(uri,
                    new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) filename = cursor.getString(0);
            }
            if (filename == null || filename.trim().isEmpty()) filename = uri.getLastPathSegment();
            if (filename != null) {
                int slash = Math.max(filename.lastIndexOf('/'), filename.lastIndexOf(':'));
                if (slash >= 0 && slash + 1 < filename.length()) filename = filename.substring(slash + 1);
            }
            pendingVaultKeyName = filename == null || filename.trim().isEmpty() ? "SSH-ключ" : filename.trim();
            showSaveKeyDialog();
        } catch (Exception e) {
            Toast.makeText(this, "Не удалось прочитать ключ: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private MaterialCardView surfaceCard() {
        MaterialCardView card = new MaterialCardView(this);
        card.setRadius(dp(18));
        card.setCardElevation(dp(1));
        card.setStrokeWidth(dp(1));
        card.setStrokeColor(resolveColor(com.google.android.material.R.attr.colorOutlineVariant, 0xFFE0E3E8));
        card.setCardBackgroundColor(resolveColor(com.google.android.material.R.attr.colorSurface, 0xFFFFFFFF));
        return card;
    }

    private MaterialButton makeButton(String label, boolean primary) {
        MaterialButton button = new MaterialButton(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setTextSize(14);
        button.setMinHeight(dp(44));
        button.setInsetTop(0);
        button.setInsetBottom(0);
        button.setCornerRadius(dp(13));
        button.setElevation(0);
        styleButton(button, primary);
        return button;
    }

    private void styleButton(MaterialButton button, boolean primary) {
        if (primary) {
            button.setBackgroundTintList(ColorStateList.valueOf(
                    resolveColor(android.R.attr.colorAccent, 0xFF2457D6)));
            button.setTextColor(0xFFFFFFFF);
            button.setStrokeWidth(0);
        } else {
            button.setBackgroundTintList(ColorStateList.valueOf(
                    resolveColor(com.google.android.material.R.attr.colorSurface, 0xFFFFFFFF)));
            button.setStrokeColor(ColorStateList.valueOf(
                    resolveColor(com.google.android.material.R.attr.colorOutlineVariant, 0xFFE0E3E8)));
            button.setStrokeWidth(dp(1));
            button.setTextColor(resolveColor(com.google.android.material.R.attr.colorOnSurface, 0xFF33415C));
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
