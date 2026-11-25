package io.github.deltaconfig;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.util.DisplayMetrics;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.SeekBar;
import android.widget.Spinner;
import android.widget.TextView;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import io.github.deltaconfig.core.ConfigCrypto;
import io.github.deltaconfig.core.ConfigPatcher;
import io.github.deltaconfig.core.OperationFailure;

/** Local, explicit configuration editing. No automatic writes or network use. */
public final class MainActivity extends Activity {
    private static final String PROJECT_URL = "https://github.com/kk041108/DeltaConfig";
    private static final int RISK_NOTICE_VERSION = 1;
    private static final String RISK_NOTICE = "本软件需要 root 权限，会读取并修改《三角洲行动》的游戏配置文件。"
        + "使用 root 或修改游戏配置可能触发反作弊检测，导致账号受限或封禁。"
        + "请充分了解并接受上述风险后再使用。";
    private static final int BG = 0xFFFFF5F9, INK = 0xFF4B2B40,
        MUTED = 0xFF705365, ACCENT = 0xFF8D315C, BORDER = 0xFFEED1E2,
        PINK = 0xFFFFC8DD, ROSE = 0xFFFFAFCC, LAVENDER = 0xFFCDB4DB,
        ICE = 0xFFBDE0FE, CARD = 0xD6FFFCFE, BOTTOM = 0xE6FFF8FC,
        DISABLED = 0xFFF4DCE7, DISABLED_INK = 0xFF947685;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private GameRepository repository;
    private GameTarget selectedTarget;
    private GameRepository.Snapshot snapshot;
    private Spinner quality, fps, gameTargetPicker;
    private SeekBar ratio;
    private EditText shortEdge;
    private static final int ERROR_LOG_LIMIT = 512 * 1024;
    private TextView statusTitle, statusBody, ratioLabel, targetLabel, limitLabel, currentLabel, gameTargetStatus;
    private Button readButton, restoreButton, resetButton, previewButton, reportButton, errorButton, rootButton, refreshTargetsButton;
    private ProgressBar progress;
    private boolean busy, initializing;
    private boolean updatingTargets;
    private AlertDialog pendingActionDialog;
    private String lastReport = "尚无操作记录。";
    private String lastErrorReport;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        selectedTarget = GameTarget.initialSelection(getSharedPreferences("game_target", MODE_PRIVATE)
            .getString("package", null), installedTargets());
        repository = new GameRepository(getApplicationContext(), selectedTarget.packageName);
        rememberTarget();
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackground(new AppBackgroundDrawable(getResources()));
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets.consumeSystemWindowInsets();
        });
        setContentView(root);
        root.requestApplyInsets();
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        LinearLayout content = column();
        content.setPadding(dp(22), dp(24), dp(22), dp(20));
        scroll.addView(content);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        LinearLayout heading = column();
        heading.setPadding(dp(12), dp(10), dp(12), dp(12));
        heading.setBackground(shape(0xB3FFFAFC, 0x00FFFFFF, 18));
        TextView eyebrow = text("本机配置工具  /  ROOT", 12, ACCENT, true);
        eyebrow.setLetterSpacing(.09f);
        heading.addView(eyebrow);
        TextView title = text("鼠鼠工具箱", 29, INK, true);
        add(heading, title, 8);
        add(heading, text("本机解密 · 自动备份 · 随时还原", 14, MUTED, false), 8);
        content.addView(heading);

        LinearLayout risk = card();
        risk.addView(text("风险告知", 17, ACCENT, true));
        add(risk, text(RISK_NOTICE, 14, INK, false), 8);
        add(content, risk, 20);

        LinearLayout gameTargetCard = card();
        gameTargetCard.addView(text("游戏发行版", 17, INK, true));
        gameTargetPicker = selectionSpinner(targetChoices());
        gameTargetPicker.setContentDescription("选择要读取、修改和还原的三角洲游戏发行版");
        gameTargetPicker.setSelection(targetIndex(selectedTarget));
        add(gameTargetCard, gameTargetPicker, 8);
        gameTargetStatus = text("", 13, MUTED, false);
        add(gameTargetCard, gameTargetStatus, 8);
        refreshTargetsButton = button("刷新已安装状态", false);
        refreshTargetsButton.setOnClickListener(view -> refreshInstalledTargets());
        add(gameTargetCard, refreshTargetsButton, 10);
        add(content, gameTargetCard, 16);

        LinearLayout connection = card();
        LinearLayout statusRow = new LinearLayout(this);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        progress = new ProgressBar(this);
        progress.setIndeterminateTintList(ColorStateList.valueOf(ACCENT));
        statusRow.addView(progress, new LinearLayout.LayoutParams(dp(24), dp(24)));
        statusTitle = text("等待读取", 17, INK, true);
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(-1,-2);
        statusParams.leftMargin = dp(12);
        statusRow.addView(statusTitle, statusParams);
        connection.addView(statusRow);
        statusBody = text("首次使用时，请在 root 管理器中允许本应用。", 14, MUTED, false);
        add(connection, statusBody, 12);
        currentLabel = text("", 13, MUTED, false);
        add(connection, currentLabel, 10);
        errorButton = button("查看本次错误", false);
        errorButton.setVisibility(View.GONE);
        errorButton.setOnClickListener(view -> showErrorDetails());
        add(connection, errorButton, 10);
        rootButton=button("授权 root",false);
        rootButton.setOnClickListener(view -> {
            if(!busy)requireRiskAcknowledgement(this::checkRootAuthorization);
        });
        add(connection,rootButton,12);
        add(connection,text("检查 root 授权；配置文件访问另行验证。已记住授权时不会再次弹窗；被拒绝请到 root 管理器允许。",12,MUTED,false),8);
        add(content, connection, 24);

        LinearLayout settings = card();
        settings.addView(text("目标设置", 19, INK, true));
        add(settings, text("画质档位", 14, MUTED, true), 20);
        quality = spinner("请选择目标画质",ConfigPatcher.QUALITY_LABELS);
        add(settings, quality, 5);
        add(settings, text("帧率档位", 14, MUTED, true), 18);
        fps = spinner("请选择目标帧率",ConfigPatcher.FPS_LABELS);
        add(settings, fps, 5);
        limitLabel = text("", 13, MUTED, false);
        add(settings, limitLabel, 10);
        add(settings, divider(), 20);
        ratioLabel = text("目标渲染比例  100%", 17, INK, true);
        add(settings, ratioLabel, 20);
        ratio = new SeekBar(this);
        ratio.setMax(75);
        ratio.setProgress(75);
        ratio.setContentDescription("待写入的目标渲染比例，25% 至 100%，不是实测值");
        ratio.setProgressTintList(controlColors(ROSE,DISABLED));
        ratio.setSecondaryProgressTintList(controlColors(PINK,DISABLED));
        ratio.setProgressBackgroundTintList(controlColors(ICE,DISABLED));
        ratio.setThumbTintList(controlColors(ACCENT,LAVENDER));
        add(settings, ratio, 12);
        LinearLayout range = new LinearLayout(this);
        TextView minimum = text("25%",12,MUTED,false), maximum = text("100% · 原生目标",12,MUTED,false);
        range.addView(minimum,new LinearLayout.LayoutParams(0,-2,1));
        maximum.setGravity(Gravity.RIGHT);
        range.addView(maximum,new LinearLayout.LayoutParams(0,-2,1));
        add(settings,range,0);
        targetLabel = text("", 13, MUTED, false);
        add(settings,targetLabel,12);
        add(settings,text("渲染基准短边（像素）",14,MUTED,true),18);
        shortEdge = new EditText(this);
        shortEdge.setSingleLine(true);
        shortEdge.setInputType(InputType.TYPE_CLASS_NUMBER);
        shortEdge.setTextColor(controlColors(INK,MUTED));
        shortEdge.setHintTextColor(MUTED);
        shortEdge.setBackgroundTintList(controlColors(ACCENT,BORDER));
        shortEdge.setHighlightColor(PINK);
        shortEdge.setTextSize(17);
        shortEdge.setMinHeight(dp(48));
        shortEdge.setText(Integer.toString(displayShortEdge()));
        shortEdge.setContentDescription("渲染基准短边，默认取当前系统显示尺寸");
        add(settings,shortEdge,4);
        add(settings,text("低于 100% 时按此短边计算；若游戏窗口尺寸不同，可手动校准。100% 使用游戏现有的 Surface 尺寸限制逻辑。",12,MUTED,false),8);
        add(content,settings,16);

        LinearLayout note = card();
        note.addView(text("写入后还需在游戏中确认",16,INK,true));
        add(note,text("配置档位不等于实测帧数。系统刷新率、设备支持状态及终极画质的独立资源上限，仍可能降低实际帧率。",13,MUTED,false),8);
        add(note,text("修改会统一设置所有画质档位的分辨率请求。",13,MUTED,false),8);
        add(note,text("游戏更新后会重新检测本机配置，认证与字段结构通过后开放修改；首次识别新库可能需要更久。",13,MUTED,false),8);
        add(content,note,16);

        LinearLayout openSource = card();
        openSource.addView(text("DeltaConfig",19,INK,true));
        add(openSource,text("源码已在 GitHub 开放，欢迎查看与交流。觉得有用，可以自愿点一颗 Star 支持项目。",13,MUTED,false),8);
        Button sourceButton=button("查看源码",false);
        sourceButton.setOnClickListener(view -> openProjectPage());
        add(openSource,sourceButton,14);
        Button starButton=button("支持项目 · Star",false);
        starButton.setOnClickListener(view -> openProjectPage());
        add(openSource,starButton,8);
        add(content,openSource,16);

        reportButton = button("查看最近操作记录", false);
        reportButton.setOnClickListener(view -> showReport());
        add(content,reportButton,12);
        Button logButton=button("查看错误日志",false);
        logButton.setOnClickListener(view -> showErrorLog());
        add(content,logButton,8);
        TextView versionLabel = text("1.10  ·  ARM64 · 按发行版检测游戏配置",11,MUTED,false);
        versionLabel.setPadding(dp(10), dp(8), dp(10), dp(8));
        versionLabel.setBackground(shape(0xCCFFFAFC, 0x00FFFFFF, 12));
        add(content,versionLabel,16);

        LinearLayout bottom = column();
        bottom.setPadding(dp(22),dp(12),dp(22),dp(14));
        bottom.setBackgroundColor(BOTTOM);
        previewButton = button("确认修改",true);
        previewButton.setOnClickListener(view -> preview());
        bottom.addView(previewButton,new LinearLayout.LayoutParams(-1,dp(52)));
        LinearLayout secondary = new LinearLayout(this);
        readButton = button("重新读取",false);
        restoreButton = button("还原最近备份",false);
        readButton.setOnClickListener(view -> load());
        restoreButton.setOnClickListener(view -> confirmRestore());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,dp(48),1);
        lp.rightMargin=dp(5);
        secondary.addView(readButton,lp);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(0,dp(48),1);
        rp.leftMargin=dp(5);
        secondary.addView(restoreButton,rp);
        add(bottom,secondary,8);
        resetButton=button("恢复默认画质设置",false);
        resetButton.setOnClickListener(view -> confirmResetDefaults());
        add(bottom,resetButton,8);
        root.addView(bottom);

        AdapterView.OnItemSelectedListener changed = new AdapterView.OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> parent, View view, int position,long id) { updateHints(); }
            public void onNothingSelected(AdapterView<?> parent) { }
        };
        quality.setOnItemSelectedListener(changed);
        fps.setOnItemSelectedListener(changed);
        ratio.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            public void onProgressChanged(SeekBar bar,int value,boolean fromUser) { updateHints(); }
            public void onStartTrackingTouch(SeekBar bar) { }
            public void onStopTrackingTouch(SeekBar bar) { }
        });
        shortEdge.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence text,int start,int count,int after) { }
            public void onTextChanged(CharSequence text,int start,int before,int count) { updateHints(); }
            public void afterTextChanged(android.text.Editable editable) { }
        });
        gameTargetPicker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (updatingTargets) return;
                GameTarget target = GameTarget.values()[position];
                if (busy) {
                    updatingTargets = true;
                    gameTargetPicker.setSelection(targetIndex(selectedTarget));
                    updatingTargets = false;
                    return;
                }
                if (target != selectedTarget) switchTarget(target);
            }
            public void onNothingSelected(AdapterView<?> parent) { }
        });
        migrateSavedError();
        updateTargetStatus();
        lastReport = targetReport(selectedTarget, "尚无操作记录。");
        updateHints();
        setBusy(false,"请先阅读风险告知","确认前不会申请 root 权限或访问游戏配置。");
        requireRiskAcknowledgement(this::load);
    }

    private boolean[] installedTargets() {
        GameTarget[] targets = GameTarget.values();
        boolean[] installed = new boolean[targets.length];
        for (int i = 0; i < targets.length; i++) {
            try { getPackageManager().getApplicationInfo(targets[i].packageName, 0); installed[i] = true; }
            catch (android.content.pm.PackageManager.NameNotFoundException | SecurityException absent) { }
        }
        return installed;
    }

    private String[] targetChoices() {
        GameTarget[] targets = GameTarget.values();
        boolean[] installed = installedTargets();
        String[] choices = new String[targets.length];
        for (int i = 0; i < targets.length; i++)
            choices[i] = targets[i].label + (installed[i] ? " · 已安装" : " · 未安装");
        return choices;
    }

    private int targetIndex(GameTarget target) {
        GameTarget[] targets = GameTarget.values();
        for (int i = 0; i < targets.length; i++) if (targets[i] == target) return i;
        throw new IllegalArgumentException("游戏发行版不在选择列表中");
    }

    private void rememberTarget() {
        getSharedPreferences("game_target", MODE_PRIVATE).edit().putString("package", selectedTarget.packageName).apply();
    }

    private void refreshInstalledTargets() {
        if (busy) return;
        updatingTargets = true;
        gameTargetPicker.setAdapter(selectionAdapter(gameTargetPicker,targetChoices()));
        gameTargetPicker.setSelection(targetIndex(selectedTarget));
        updatingTargets = false;
        updateTargetStatus();
    }

    private void updateTargetStatus() {
        boolean installed = installedTargets()[targetIndex(selectedTarget)];
        gameTargetStatus.setText(selectedTarget.label + (installed ? " · 已安装" : " · 未安装") + "\n"
            + (selectedTarget.international ? "格式自动检测，实机待验证。认证与字段结构通过后才能修改。"
                : "读取时核对本发行版的配置、认证和字段结构。")
            + (installed ? "" : "\n可保留此选择；读取时会提示当前发行版未安装。"));
    }

    private void switchTarget(GameTarget target) {
        if (busy || target == selectedTarget) return;
        if (pendingActionDialog != null) pendingActionDialog.dismiss();
        selectedTarget = target;
        repository = new GameRepository(getApplicationContext(), target.packageName);
        snapshot = null;
        rememberTarget();
        clearCurrentError();
        lastReport = targetReport(target, "尚无操作记录，请重新读取此发行版的配置。");
        currentLabel.setText("尚未读取 " + target.label + " 的配置。");
        initializing = true;
        quality.setSelection(0); fps.setSelection(0); ratio.setProgress(75);
        initializing = false;
        updateTargetStatus();
        setBusy(false, "已选择 " + target.label, "请点击“重新读取”。修改和还原仅针对当前所选发行版。");
        updateHints();
    }

    private boolean isCurrentTarget(GameRepository expected, GameTarget target) {
        return !isDestroyed() && repository == expected && selectedTarget == target;
    }

    private String targetReport(GameTarget target, String report) {
        return "发行版：" + target.label + (target.international ? "\n国际服格式自动检测，实机待验证。" : "") + "\n\n" + report;
    }

    private void showActionDialog(AlertDialog dialog) {
        if (pendingActionDialog != null) pendingActionDialog.dismiss();
        pendingActionDialog = dialog;
        dialog.setOnDismissListener(ignored -> { if (pendingActionDialog == dialog) pendingActionDialog = null; });
        dialog.show();
    }

    private void openProjectPage() {
        try {
            Intent page=new Intent(Intent.ACTION_VIEW,Uri.parse(PROJECT_URL));
            page.addCategory(Intent.CATEGORY_BROWSABLE);
            startActivity(page);
        } catch(ActivityNotFoundException | SecurityException error) {
            new AlertDialog.Builder(this).setTitle("无法打开项目页面")
                .setMessage("当前没有可用的浏览器，或系统阻止打开链接。可以复制项目地址后在浏览器中打开。")
                .setNegativeButton("关闭",null).setPositiveButton("复制链接",(dialog,which) -> {
                    ClipboardManager clipboard=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
                    if(clipboard!=null)clipboard.setPrimaryClip(ClipData.newPlainText("DeltaConfig 项目地址",PROJECT_URL));
                }).show();
        }
    }

    private boolean riskAcknowledged() {
        return getSharedPreferences("risk_notice", MODE_PRIVATE)
            .getInt("acknowledged_version", 0) >= RISK_NOTICE_VERSION;
    }

    private void checkRootAuthorization() {
        if(busy)return;
        if(!riskAcknowledged()) { requireRiskAcknowledgement(this::checkRootAuthorization); return; }
        snapshot=null;
        final GameRepository operationRepository=repository;
        final GameTarget operationTarget=selectedTarget;
        currentLabel.setText("检查授权后，请重新读取游戏配置。");
        setBusy(true,"正在检查 root 授权","正在请求 root 并核对进程身份；此次不会读取或修改游戏配置。");
        worker.execute(() -> {
            try {
                operationRepository.checkRootAuthorization();
                runOnUiThread(() -> {
                    if(!isCurrentTarget(operationRepository,operationTarget))return;
                    clearCurrentError();
                    lastReport=targetReport(operationTarget,"root 授权检查成功\n已确认 root 身份。游戏配置访问尚待单独验证。");
                    setBusy(false,"root 已授权","授权检查通过。请点击“重新读取”验证游戏配置。已记住授权时不会再次弹出授权框。");
                });
            } catch(Exception error) {
                fail(operationRepository,operationTarget,"root 授权检查失败",OperationFailure.wrap("检查 root 授权","验证 root 身份",operationTarget.packageName,error)
                    .state("未写入游戏配置","无需回滚",null));
            }
        });
    }

    private void updateRootButton() {
        if(rootButton==null)return;
        rootButton.setText(repository.hasRootAuthorization()?"重新授权 root":"授权 root");
        rootButton.setEnabled(!busy);
    }

    private void requireRiskAcknowledgement(Runnable next) {
        if (riskAcknowledged()) { next.run(); return; }
        AlertDialog dialog = new AlertDialog.Builder(this)
            .setTitle("使用前风险告知")
            .setMessage(RISK_NOTICE + "\n\n选择“退出”将关闭应用，不申请 root 权限，也不读取或修改游戏配置。")
            .setCancelable(false)
            .setNegativeButton("退出", (prompt, which) -> finish())
            .setPositiveButton("已知晓风险，继续", (prompt, which) -> {
                getSharedPreferences("risk_notice", MODE_PRIVATE).edit()
                    .putInt("acknowledged_version", RISK_NOTICE_VERSION).apply();
                next.run();
            }).create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.show();
    }

    private void load() {
        if (busy) return;
        if (!riskAcknowledged()) { requireRiskAcknowledgement(this::load); return; }
        final GameRepository operationRepository=repository;
        final GameTarget operationTarget=selectedTarget;
        setBusy(true,"正在检测 "+operationTarget.label,"正在检查 root、识别认证材料并校验配置；首次识别新库可能需要更久…");
        snapshot=null;
        final int renderBase=displayShortEdge();
        worker.execute(() -> {
            try {
                GameRepository.Snapshot found=operationRepository.load();
                byte[] key=ConfigCrypto.deriveKey(found.fixedMask,found.gameplay);
                final int q,f;
                try {
                    String plain=ConfigCrypto.decodeIni(found.engine,key);
                    q=ConfigPatcher.getInt(plain,"DFMPerfGearConfig","DFMQualityLevel",-1);
                    f=ConfigPatcher.getInt(plain,"DFMPerfGearConfig","DFMFPSLevel",-1);
                } finally { java.util.Arrays.fill(key,(byte)0); }
                final int percent=readRatio(found,renderBase);
                runOnUiThread(() -> {
                    if (!isCurrentTarget(operationRepository,operationTarget)) return;
                    snapshot=found;
                    initializing=true;
                    selectValue(quality,ConfigPatcher.QUALITY_VALUES,q);
                    selectValue(fps,ConfigPatcher.FPS_VALUES,f);
                    ratio.setProgress(percent-25);
                    initializing=false;
                    clearCurrentError();
                    currentLabel.setText(currentSettings(operationTarget,q,f,found.versionName));
                    setBusy(false,"配置兼容性检测通过",found.compatibilityDescription+"\n可选择目标设置并确认修改。");
                    lastReport=targetReport(operationTarget,"读取成功\n游戏版本："+found.versionName+" ("+found.versionCode+")\n兼容性检测："+found.compatibilityDescription+"\n配置认证与字段结构：通过");
                    updateHints();
                });
            } catch (Exception error) {
                fail(operationRepository,operationTarget,"读取配置失败",OperationFailure.wrap("读取配置","读取并验证本机游戏文件",operationTarget.packageName,error));
            }
        });
    }

    private void preview() {
        if (busy || snapshot==null) return;
        if (!riskAcknowledged()) { requireRiskAcknowledgement(this::preview); return; }
        final int base;
        try {
            base=Integer.parseInt(shortEdge.getText().toString().trim());
            if (base<200 || base>8192) throw new NumberFormatException();
        } catch (NumberFormatException invalid) {
            shortEdge.setError("请输入 200–8192 之间的短边像素值"); return;
        }
        final GameRepository operationRepository=repository;
        final GameTarget operationTarget=selectedTarget;
        final GameRepository.Snapshot before=snapshot;
        if(!targetSettingsSelected())return;
        final int q=ConfigPatcher.QUALITY_VALUES[quality.getSelectedItemPosition()-1];
        final int f=ConfigPatcher.FPS_VALUES[fps.getSelectedItemPosition()-1];
        final int percent=ratio.getProgress()+25;
        setBusy(true,"正在准备预览","检查修改范围并生成新的认证配置…");
        worker.execute(() -> {
            try {
                ConfigPatcher.Plan plan=ConfigPatcher.plan(before.engine,before.game,before.gameplay,before.fixedMask,q,f,percent,base);
                runOnUiThread(() -> {
                    if(!isCurrentTarget(operationRepository,operationTarget)) return;
                    clearCurrentError();
                    setBusy(false,"修改预览已就绪","尚未写入，请确认目标设置。");
                    lastReport=targetReport(operationTarget,"修改预览已就绪\n\n"+plan.summary+"\n\n尚未写入游戏配置。");
                    String details=targetReport(operationTarget,plan.summary)+"\n\n实际帧率与渲染效果须在游戏中确认。"
                        + "\n\n风险告知\n" + RISK_NOTICE;
                    showActionDialog(new AlertDialog.Builder(this).setTitle("确认目标设置").setMessage(details)
                        .setNegativeButton("返回",null).setPositiveButton("知晓风险并写入",(dialog,which) -> apply(operationRepository,operationTarget,before,plan)).create());
                });
            } catch(Exception error) {
                fail(operationRepository,operationTarget,"生成修改预览失败",OperationFailure.wrap("生成修改预览","解密、修改并重新封装配置",failurePath(before,error),error)
                    .state("本次尚未写入游戏配置","未执行回滚",null));
            }
        });
    }

    private void apply(GameRepository operationRepository,GameTarget operationTarget,GameRepository.Snapshot before,ConfigPatcher.Plan plan) {
        if(busy || !isCurrentTarget(operationRepository,operationTarget) || snapshot!=before
                || !operationTarget.packageName.equals(before.packageName)) return;
        if (!riskAcknowledged()) { requireRiskAcknowledgement(() -> apply(operationRepository,operationTarget,before,plan)); return; }
        setBusy(true,"正在写入","正在应用目标设置并验证结果…");
        worker.execute(() -> {
            final String result;
            try {
                result=operationRepository.apply(before,plan.engine,plan.game);
            } catch(Exception error) {
                runOnUiThread(() -> { if(isCurrentTarget(operationRepository,operationTarget))snapshot=null; });
                fail(operationRepository,operationTarget,"修改配置时发生错误",OperationFailure.wrap("修改配置","备份、提交及回读校验",configurationPaths(before),error));
                return;
            }
            runOnUiThread(() -> {
                if(!isCurrentTarget(operationRepository,operationTarget))return;
                clearCurrentError();
                lastReport=targetReport(operationTarget,"配置写入完成\n\n"+plan.summary+"\n\n配置校验：通过\n实际游戏效果：尚未验证");
                refreshAfterCommit(operationRepository,operationTarget,"写入",result);
            });
        });
    }

    private void confirmRestore() {
        if(busy)return;
        if (!riskAcknowledged()) { requireRiskAcknowledgement(this::confirmRestore); return; }
        final GameRepository operationRepository=repository;
        final GameTarget operationTarget=selectedTarget;
        showActionDialog(new AlertDialog.Builder(this).setTitle("还原最近备份")
            .setMessage(targetReport(operationTarget,"将恢复此发行版最近一次修改前保存的设置。")
                + "\n\n风险告知\n" + RISK_NOTICE)
            .setNegativeButton("返回",null).setPositiveButton("还原",(dialog,which) -> restore(operationRepository,operationTarget)).create());
    }

    private void restore(GameRepository operationRepository,GameTarget operationTarget) {
        if (busy || !isCurrentTarget(operationRepository,operationTarget)) return;
        if (!riskAcknowledged()) { requireRiskAcknowledgement(() -> restore(operationRepository,operationTarget)); return; }
        setBusy(true,"正在还原","正在核对备份所属设备、版本和配置认证…");
        worker.execute(() -> {
            try {
                String result=operationRepository.restoreLatest();
                runOnUiThread(() -> {
                    if(!isCurrentTarget(operationRepository,operationTarget))return;
                    clearCurrentError();
                    lastReport=targetReport(operationTarget,"还原完成\n已恢复此发行版最近备份的设置并通过校验。\n实际游戏效果：尚未验证");
                    refreshAfterCommit(operationRepository,operationTarget,"还原",result);
                });
            } catch(Exception error) {
                runOnUiThread(() -> { if(isCurrentTarget(operationRepository,operationTarget))snapshot=null; });
                fail(operationRepository,operationTarget,"还原配置时发生错误",OperationFailure.wrap("还原配置","核验备份并恢复配置",operationTarget.packageName,error));
            }
        });
    }

    private void confirmResetDefaults() {
        if(busy || snapshot==null)return;
        if(!riskAcknowledged()) { requireRiskAcknowledgement(this::confirmResetDefaults); return; }
        final GameRepository operationRepository=repository;
        final GameTarget operationTarget=selectedTarget;
        final GameRepository.Snapshot before=snapshot;
        showActionDialog(new AlertDialog.Builder(this).setTitle("恢复默认画质设置")
            .setMessage(targetReport(operationTarget,"将清除画质、帧率和渲染比例覆盖设置，进入游戏后由游戏重新生成默认设置。实际默认档位由游戏决定。"
                + "不会清除账号、下载资源或其他游戏数据。")+"\n\n风险告知\n"+RISK_NOTICE)
            .setNegativeButton("返回",null).setPositiveButton("恢复默认",(dialog,which) -> resetDefaults(operationRepository,operationTarget,before)).create());
    }

    private void resetDefaults(GameRepository operationRepository,GameTarget operationTarget,GameRepository.Snapshot before) {
        if(busy || before==null || snapshot!=before || !isCurrentTarget(operationRepository,operationTarget)
                || !operationTarget.packageName.equals(before.packageName))return;
        if(!riskAcknowledged()) { requireRiskAcknowledgement(() -> resetDefaults(operationRepository,operationTarget,before)); return; }
        setBusy(true,"正在恢复默认设置","正在重置画质配置并验证结果…");
        worker.execute(() -> {
            try {
                operationRepository.resetDefaults(before);
            } catch(Exception error) {
                runOnUiThread(() -> { if(isCurrentTarget(operationRepository,operationTarget))snapshot=null; });
                fail(operationRepository,operationTarget,"恢复默认画质设置失败",OperationFailure.wrap("恢复默认画质设置","重置自定义设置并核验结果",configurationPaths(before),error));
                return;
            }
            runOnUiThread(() -> {
                if(!isCurrentTarget(operationRepository,operationTarget))return;
                snapshot=null;
                clearCurrentError();
                currentLabel.setText("画质、帧率和渲染覆盖已清除，实际默认档位由游戏决定。");
                initializing=true;
                quality.setSelection(0);fps.setSelection(0);
                initializing=false;
                lastReport=targetReport(operationTarget,"恢复默认画质设置完成\n已清除画质、帧率和渲染覆盖；进入游戏后由游戏重新生成默认设置。实际默认档位由游戏决定。");
                setBusy(false,"恢复默认设置已完成","已清除画质、帧率和渲染覆盖；进入游戏后由游戏重新生成默认设置。实际默认档位由游戏决定。");
                new AlertDialog.Builder(this).setTitle("恢复默认设置完成")
                    .setMessage("请进入游戏生成默认画质设置，正常退出后点击“重新读取”。需要撤销时可使用“还原最近备份”。")
                    .setPositiveButton("知道了",null).show();
            });
        });
    }

    /** The commit succeeded. A later display refresh must never be reported as a failed write. */
    private void refreshAfterCommit(GameRepository operationRepository,GameTarget operationTarget,String completed,String result) {
        if(!isCurrentTarget(operationRepository,operationTarget))return;
        snapshot=null;
        setBusy(true,completed+"已完成，正在刷新","已完成配置"+completed+"和文件校验，正在重新读取当前状态…");
        final int renderBase=displayShortEdge();
        worker.execute(() -> {
            try {
                GameRepository.Snapshot fresh=operationRepository.load();
                byte[] key=ConfigCrypto.deriveKey(fresh.fixedMask,fresh.gameplay);
                final int q,f;
                try {
                    String plain=ConfigCrypto.decodeIni(fresh.engine,key);
                    q=ConfigPatcher.getInt(plain,"DFMPerfGearConfig","DFMQualityLevel",-1);
                    f=ConfigPatcher.getInt(plain,"DFMPerfGearConfig","DFMFPSLevel",-1);
                } finally { java.util.Arrays.fill(key,(byte)0); }
                final int percent=readRatio(fresh,renderBase);
                runOnUiThread(() -> {
                    if(!isCurrentTarget(operationRepository,operationTarget))return;
                    snapshot=fresh;
                    initializing=true;
                    selectValue(quality,ConfigPatcher.QUALITY_VALUES,q);
                    selectValue(fps,ConfigPatcher.FPS_VALUES,f);
                    ratio.setProgress(percent-25);
                    initializing=false;
                    clearCurrentError();
                    currentLabel.setText(currentSettings(operationTarget,q,f,fresh.versionName));
                    setBusy(false,completed+"已完成并校验","当前状态已刷新。");
                    updateHints();
                    new AlertDialog.Builder(this).setTitle(completed+"完成")
                        .setMessage(targetReport(operationTarget,"设置已"+completed+"并通过校验。请重新进入游戏确认实际效果。"))
                        .setPositiveButton("知道了",null).show();
                });
            } catch(Exception error) {
                OperationFailure diagnostic=OperationFailure.wrap(completed+"后刷新","提交完成后重新读取配置",operationTarget.packageName,error)
                    .state("已完成"+completed+"并通过文件校验","提交已完成；未因本次刷新失败执行回滚",backupPath(result))
                    .hint("本次"+completed+"已经成功，状态暂未刷新，可重新读取。");
                appendErrorLog(targetReport(operationTarget,completed+"已完成，状态暂未刷新\n\n"+OperationFailure.format(diagnostic)));
                runOnUiThread(() -> {
                    if(!isCurrentTarget(operationRepository,operationTarget))return;
                    snapshot=null;
                    clearCurrentError();
                    lastReport+="\n\n状态暂未刷新，可重新读取。";
                    setBusy(false,completed+"已完成","设置已"+completed+"并通过校验。状态暂未刷新，可重新读取。");
                });
            }
        });
    }

    private String configurationPaths(GameRepository.Snapshot value) {
        return "Engine.ini: "+value.enginePath+"\nGame.ini: "+value.gamePath+"\nUserGameplay.ini: "+value.gameplayPath;
    }

    private String failurePath(GameRepository.Snapshot value,Exception error) {
        if(error instanceof OperationFailure) {
            String path=((OperationFailure)error).getPath();
            if("Engine.ini".equals(path))return value.enginePath;
            if("Game.ini".equals(path))return value.gamePath;
            if("UserGameplay.ini".equals(path))return value.gameplayPath;
        }
        return configurationPaths(value);
    }

    private String backupPath(String result) {
        java.util.regex.Matcher path=java.util.regex.Pattern.compile("/data/adb/deltaconfig/[^\\s；;]+") .matcher(result);
        return path.find()?path.group():null;
    }

    private void updateHints() {
        if(ratio==null || shortEdge==null || initializing)return;
        int percent=ratio.getProgress()+25;
        ratioLabel.setText("目标渲染比例  "+percent+"%"+(percent==100?" · 原生目标":""));
        int pixels=0;
        try {pixels=Integer.parseInt(shortEdge.getText().toString().trim());}catch(NumberFormatException ignored){}
        targetLabel.setText((percent==100?"所有档位使用 Surface 原尺寸目标；系统缩放仍可能影响最终尺寸。":
            "场景短边请求："+Math.round(pixels*percent/100f)+" 像素 · 比例基于上方校准值")
            +"\n此处为待写入目标，不代表游戏当前的实测渲染比例。");
        int q=quality==null?-1:quality.getSelectedItemPosition()-1;
        int fpsIndex=fps==null?-1:fps.getSelectedItemPosition()-1;
        int selectedFps=fpsIndex<0?0:ConfigPatcher.fpsForInternal(ConfigPatcher.FPS_VALUES[fpsIndex]);
        String hint=q==5?"终极档有独立的资源表帧率上限；本应用不会修改该表。":"游戏可能按设备支持状态限制实际帧率。";
        if(selectedFps>=90)hint+=" "+selectedFps+" 帧还要求系统向游戏报告至少 "+selectedFps+"Hz。";
        limitLabel.setText(hint);
        if(previewButton!=null)previewButton.setEnabled(!busy && riskAcknowledged() && snapshot!=null && targetSettingsSelected());
    }

    private int inferRatio(byte[] game,int base) {
        String value=new String(game,java.nio.charset.StandardCharsets.UTF_8);
        java.util.regex.Matcher matcher=java.util.regex.Pattern.compile("(?:UltraLowResolution|LowResolution|MidResolution|HighResolution|UltraHighResolution|SuperResolution)=(\\d+)").matcher(value);
        int first=-1,count=0;
        while(matcher.find()){
            int current=Integer.parseInt(matcher.group(1));
            if(first<0)first=current;
            else if(first!=current)return 75;
            count++;
        }
        if(count==90 && first>=8192)return 100;
        if(count==90 && base>0)return Math.max(25,Math.min(100,(int)Math.round(first*100.0/base)));
        return 100;
    }

    private int readRatio(GameRepository.Snapshot value,int base) throws OperationFailure {
        try { return inferRatio(value.game,base); }
        catch(RuntimeException error) {
            throw OperationFailure.wrap("读取渲染比例","解析 Game.ini 的分辨率数值",value.gamePath,error)
                .hint("Game.ini 中的分辨率数值无法解析；请保留此报告和原文件，不要继续覆盖配置。");
        }
    }

    private void fail(GameRepository operationRepository,GameTarget operationTarget,String title,Exception error) {
        boolean logged=appendErrorLog(targetReport(operationTarget,title+"\n\n"+OperationFailure.format(error)));
        final String detail=logged?OperationFailure.userReport(error):OperationFailure.userReport(error)
            .replace("详细诊断已保存至本机错误日志。","本次错误日志未能保存；以上操作失败信息仍有效。");
        runOnUiThread(() -> {
            if(!isCurrentTarget(operationRepository,operationTarget))return;
            lastErrorReport=targetReport(operationTarget,title+"\n\n"+detail);
            lastReport=lastErrorReport;
            errorButton.setVisibility(View.VISIBLE);
            setBusy(false,title,detail.length()>1200?detail.substring(0,1200)+"\n\n点击“查看本次错误”阅读原因。":detail);
            showErrorDetails();
        });
    }

    private void clearCurrentError() {
        lastErrorReport=null;
        errorButton.setVisibility(View.GONE);
    }

    private synchronized byte[] readErrorLog() throws java.io.IOException {
        java.io.File log=new java.io.File(getFilesDir(),"error-history.log");
        if(!log.isFile())return new byte[0];
        try(java.io.RandomAccessFile file=new java.io.RandomAccessFile(log,"r")) {
            int length=(int)Math.min(file.length(),ERROR_LOG_LIMIT);
            byte[] data=new byte[length];
            file.seek(file.length()-length);
            file.readFully(data);
            return data;
        }
    }

    private synchronized boolean appendErrorLog(String report) {
        try {
            byte[] previous=readErrorLog();
            String stamp=new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z",java.util.Locale.ROOT)
                .format(new java.util.Date());
            byte[] entry=("\n\n===== "+stamp+" =====\n"+report+"\n")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] joined=new byte[previous.length+entry.length];
            System.arraycopy(previous,0,joined,0,previous.length);
            System.arraycopy(entry,0,joined,previous.length,entry.length);
            int start=Math.max(0,joined.length-ERROR_LOG_LIMIT);
            // Trimming a bounded log must not leave a partial UTF-8 character at its start.
            while(start<joined.length && (joined[start]&0xC0)==0x80)start++;
            try(java.io.FileOutputStream file=openFileOutput("error-history.log",MODE_PRIVATE)) {
                file.write(joined,start,joined.length-start);
            }
            return true;
        } catch(java.io.IOException ignored) {
            // Logging must not replace the original configuration failure.
            return false;
        }
    }

    private void migrateSavedError() {
        android.content.SharedPreferences preferences=getSharedPreferences("error_log",MODE_PRIVATE);
        if(preferences.getBoolean("last_error_migrated",false))return;
        java.io.File legacy=new java.io.File(getFilesDir(),"last-error.txt");
        boolean migrated=!legacy.isFile();
        if(!migrated) {
            try(java.io.RandomAccessFile file=new java.io.RandomAccessFile(legacy,"r")) {
                int length=(int)Math.min(file.length(),ERROR_LOG_LIMIT/2);
                byte[] data=new byte[length];
                file.seek(file.length()-length);
                file.readFully(data);
                migrated=appendErrorLog("旧版错误记录\n"+new String(data,java.nio.charset.StandardCharsets.UTF_8));
            } catch(java.io.IOException ignored) { }
        }
        if(migrated) {
            preferences.edit().putBoolean("last_error_migrated",true).apply();
            deleteFile("last-error.txt");
        }
    }

    private void showErrorLog() {
        final String report;
        try {
            byte[] data=readErrorLog();
            report=data.length==0?"暂无错误日志。":new String(data,java.nio.charset.StandardCharsets.UTF_8);
        } catch(java.io.IOException error) {
            new AlertDialog.Builder(this).setTitle("错误日志读取失败")
                .setMessage("无法读取本应用保存的错误日志；不会影响游戏配置。")
                .setPositiveButton("知道了",null).show();
            return;
        }
        ScrollView scroll=new ScrollView(this);
        TextView detail=text(report,13,INK,false);
        detail.setTextIsSelectable(true);
        detail.setPadding(dp(20),dp(12),dp(20),dp(16));
        scroll.addView(detail);
        new AlertDialog.Builder(this).setTitle("错误日志（历史记录）").setView(scroll)
            .setNegativeButton("关闭",null).setPositiveButton("复制日志",(dialog,which) -> {
                ClipboardManager clipboard=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
                clipboard.setPrimaryClip(ClipData.newPlainText("鼠鼠工具箱错误日志",report));
            }).show();
    }

    private void showErrorDetails() {
        if(lastErrorReport==null || lastErrorReport.isEmpty())return;
        final String report=lastErrorReport;
        ScrollView scroll=new ScrollView(this);
        TextView detail=text(report,14,INK,false);
        detail.setTextIsSelectable(true);
        detail.setPadding(dp(20),dp(12),dp(20),dp(16));
        scroll.addView(detail);
        new AlertDialog.Builder(this).setTitle("本次错误").setView(scroll)
            .setNegativeButton("关闭",null).setPositiveButton("复制报错",(dialog,which) -> {
                ClipboardManager clipboard=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
                clipboard.setPrimaryClip(ClipData.newPlainText("鼠鼠工具箱错误详情",report));
            }).show();
    }

    private void setBusy(boolean value,String title,String detail) {
        busy=value;
        progress.setVisibility(value?View.VISIBLE:View.GONE);
        statusTitle.setText(title);
        statusBody.setText(detail);
        boolean ready = !value && riskAcknowledged();
        readButton.setEnabled(ready);
        restoreButton.setEnabled(ready);
        previewButton.setEnabled(ready && snapshot!=null && targetSettingsSelected());
        resetButton.setEnabled(ready && snapshot!=null);
        quality.setEnabled(ready && snapshot!=null);
        fps.setEnabled(ready && snapshot!=null);
        ratio.setEnabled(ready && snapshot!=null);
        shortEdge.setEnabled(ready && snapshot!=null);
        gameTargetPicker.setEnabled(!value);
        refreshTargetsButton.setEnabled(!value);
        updateRootButton();
    }

    private void showReport() {
        new AlertDialog.Builder(this).setTitle("最近操作记录").setMessage(lastReport)
            .setNegativeButton("关闭",null).setPositiveButton("复制记录",(dialog,which) -> {
                ClipboardManager clipboard=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
                clipboard.setPrimaryClip(ClipData.newPlainText("鼠鼠工具箱操作记录",lastReport));
            }).show();
    }

    private String fpsLabel(int internal) {
        for(int i=0;i<ConfigPatcher.FPS_VALUES.length;i++)if(ConfigPatcher.FPS_VALUES[i]==internal)return ConfigPatcher.FPS_LABELS[i];
        return "其他帧率档位（"+internal+"）";
    }

    private void selectValue(Spinner spinner,int[] values,int wanted) {
        for(int i=0;i<values.length;i++)if(values[i]==wanted){spinner.setSelection(i+1);return;}
        spinner.setSelection(0);
    }

    private boolean targetSettingsSelected() {
        return quality!=null && fps!=null && quality.getSelectedItemPosition()>0 && fps.getSelectedItemPosition()>0;
    }

    private String currentSettings(GameTarget target,int q,int f,String version) {
        String qualityText=q<0?"画质由游戏生成":ConfigPatcher.qualityLabel(q);
        String fpsText=f<0?"帧率由游戏生成":fpsLabel(f);
        return "发行版："+target.label+"\n当前："+qualityText+" / "+fpsText+"\n游戏版本："+version;
    }

    private int displayShortEdge() {
        DisplayMetrics metrics=new DisplayMetrics();
        getWindowManager().getDefaultDisplay().getRealMetrics(metrics);
        return Math.max(200,Math.min(metrics.widthPixels,metrics.heightPixels));
    }

    private Spinner spinner(String prompt,String[] labels) {
        String[] choices=new String[labels.length+1];
        choices[0]=prompt;
        System.arraycopy(labels,0,choices,1,labels.length);
        return selectionSpinner(choices);
    }

    private ArrayAdapter<String> selectionAdapter(final Spinner spinner,String[] choices) {
        ArrayAdapter<String> adapter=new ArrayAdapter<String>(this,android.R.layout.simple_spinner_item,choices) {
            @Override public View getView(int position,View recycled,ViewGroup parent) {
                TextView row=(TextView)super.getView(position,recycled,parent);
                row.setTextColor(controlColors(INK,MUTED));
                row.setTextSize(16);
                row.setSingleLine(false);
                row.setMaxLines(2);
                row.setMinimumHeight(dp(48));
                row.setGravity(Gravity.CENTER_VERTICAL);
                row.setPadding(dp(8),dp(6),dp(8),dp(6));
                return row;
            }
            @Override public View getDropDownView(int position,View recycled,ViewGroup parent) {
                TextView row=(TextView)super.getDropDownView(position,recycled,parent);
                row.setTextColor(INK);
                row.setTextSize(16);
                row.setSingleLine(false);
                row.setMaxLines(2);
                row.setMinimumHeight(dp(48));
                row.setPadding(dp(14),dp(10),dp(14),dp(10));
                StateListDrawable background=new StateListDrawable();
                background.addState(new int[]{android.R.attr.state_pressed},shape(PINK,BORDER,10));
                background.addState(new int[]{android.R.attr.state_focused},shape(PINK,ACCENT,10));
                background.addState(new int[]{android.R.attr.state_checked},shape(PINK,BORDER,10));
                background.addState(new int[]{},shape(position==spinner.getSelectedItemPosition()?PINK:0xFFFFF8FC,BORDER,10));
                row.setBackground(background);
                if(row instanceof android.widget.CheckedTextView)
                    ((android.widget.CheckedTextView)row).setCheckMarkTintList(ColorStateList.valueOf(ACCENT));
                return row;
            }
        };
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        return adapter;
    }

    private Spinner selectionSpinner(String[] choices) {
        final Spinner spinner=new Spinner(this);
        spinner.setAdapter(selectionAdapter(spinner,choices));
        spinner.setMinimumHeight(dp(48));
        spinner.setPadding(dp(4),0,dp(4),0);
        spinner.setBackgroundTintList(new ColorStateList(
            new int[][]{new int[]{-android.R.attr.state_enabled},new int[]{android.R.attr.state_focused},new int[]{android.R.attr.state_pressed},new int[]{}},
            new int[]{BORDER,ACCENT,ACCENT,ACCENT}));
        spinner.setPopupBackgroundDrawable(shape(0xFFFFF8FC,BORDER,14));
        return spinner;
    }

    private Button button(String title,boolean primary) {
        Button button=new Button(this);
        button.setText(title);button.setAllCaps(false);button.setTextSize(15);button.setMinHeight(dp(48));
        button.setTextColor(new ColorStateList(
            new int[][]{new int[]{-android.R.attr.state_enabled},new int[]{android.R.attr.state_pressed},new int[]{android.R.attr.state_focused},new int[]{}},
            new int[]{DISABLED_INK,INK,INK,primary?INK:ACCENT}));
        StateListDrawable background=new StateListDrawable();
        background.addState(new int[]{-android.R.attr.state_enabled},shape(DISABLED,BORDER,13));
        background.addState(new int[]{android.R.attr.state_pressed},shape(primary?0xFFF69ABD:PINK,ACCENT,13));
        background.addState(new int[]{android.R.attr.state_focused},shape(primary?ROSE:0xFFFFECF4,ACCENT,13));
        background.addState(new int[]{},shape(primary?ROSE:0xF2FFF3F8,primary?0xFFE697B7:LAVENDER,13));
        button.setBackgroundTintList(null);
        button.setBackground(background);
        return button;
    }

    private ColorStateList controlColors(int enabled,int disabled) {
        return new ColorStateList(new int[][]{new int[]{-android.R.attr.state_enabled},new int[]{}},
            new int[]{disabled,enabled});
    }

    private GradientDrawable shape(int fill,int stroke,int radius) {
        GradientDrawable background=new GradientDrawable();
        background.setColor(fill);
        background.setCornerRadius(dp(radius));
        background.setStroke(dp(1),stroke);
        return background;
    }

    private LinearLayout column(){LinearLayout layout=new LinearLayout(this);layout.setOrientation(LinearLayout.VERTICAL);return layout;}
    private LinearLayout card(){LinearLayout layout=column();layout.setPadding(dp(18),dp(18),dp(18),dp(18));layout.setBackground(shape(CARD,BORDER,18));return layout;}
    private TextView text(String value,int size,int color,boolean bold){TextView view=new TextView(this);view.setText(value);view.setTextSize(size);view.setTextColor(color);view.setLineSpacing(dp(3),1);if(bold)view.setTypeface(Typeface.DEFAULT,Typeface.BOLD);return view;}
    private View divider(){View view=new View(this);view.setBackgroundColor(BORDER);view.setMinimumHeight(dp(1));return view;}
    private void add(LinearLayout parent,View child,int margin){LinearLayout.LayoutParams params=new LinearLayout.LayoutParams(-1,child.getMinimumHeight()==dp(1)?dp(1):-2);params.topMargin=dp(margin);parent.addView(child,params);}
    private int dp(int value){return Math.round(value*getResources().getDisplayMetrics().density);}
    @Override protected void onDestroy(){
        if(pendingActionDialog!=null)pendingActionDialog.dismiss();
        super.onDestroy();worker.shutdown();
    }
}
