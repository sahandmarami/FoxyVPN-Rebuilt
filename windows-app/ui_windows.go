//go:build windows

package main

// Native Windows UI built on Win32 common controls (lxn/walk): a real
// application window — no WebView2, no browser. The tray icon shares the same
// message loop, so "Exit" always terminates the process instantly.

import (
        "fmt"
        "os"
        "path/filepath"
        "runtime"
        "strings"
        "sync/atomic"
        "time"

        "github.com/lxn/walk"
        d "github.com/lxn/walk/declarative"
        "github.com/lxn/win"
)

type nativeUI struct {
        core *Core
        mw   *walk.MainWindow
        ni   *walk.NotifyIcon

        icoApp, icoOn, icoOff *walk.Icon

        statusLbl  *walk.Label
        detailLbl  *walk.Label
        btnToggle  *walk.PushButton
        accountLbl *walk.Label
        serverCB   *walk.ComboBox
        chkProxy   *walk.CheckBox
        trafficLbl *walk.Label
        logTE      *walk.TextEdit

        serverOpts   []ServerOption
        logLines     []string
        logSeq       int
        suppressCombo bool
        suppressChk   bool
        aToggle      *walk.Action
}

// startNativeWindow blocks on the Win32 message loop until the app exits.
// Returns false only if the window could not be created (caller falls back to
// the browser panel).
func startNativeWindow(core *Core, panelURL, dataDir string) bool {
        runtime.LockOSThread()

        ui := &nativeUI{core: core}
        ui.icoApp, ui.icoOn, ui.icoOff = loadWalkIcons(dataDir)

        if uerr := (d.MainWindow{
                AssignTo: &ui.mw,
                Title:    "FoxyVPN",
                MinSize:  d.Size{Width: 450, Height: 540},
                Size:     d.Size{Width: 480, Height: 620},
                Font:     d.Font{Family: "Tahoma", PointSize: 9},
                Layout:   d.VBox{Margins: d.Margins{Left: 14, Top: 12, Right: 14, Bottom: 12}, Spacing: 6},
                Children: []d.Widget{
                        d.Label{AssignTo: &ui.statusLbl, Text: "…", TextColor: walk.RGB(90, 90, 90),
                                Font: d.Font{Family: "Tahoma", PointSize: 14, Bold: true}},
                        d.Label{AssignTo: &ui.detailLbl, Text: "", TextColor: walk.RGB(120, 120, 120)},
                        d.VSpacer{Size: 4},
                        d.PushButton{AssignTo: &ui.btnToggle, Text: "اتصال", MinSize: d.Size{Height: 44},
                                Font:      d.Font{Family: "Tahoma", PointSize: 12, Bold: true},
                                OnClicked: func() { ui.onToggle() }},
                        d.VSpacer{Size: 6},
                        d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
                                d.Label{AssignTo: &ui.accountLbl, Text: "حساب: —"},
                                d.HSpacer{},
                                d.PushButton{Text: "ورود / تغییر حساب", OnClicked: func() { openAccountDialog(ui) }},
                        }},
                        d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
                                d.Label{Text: "سرور:"},
                                d.ComboBox{AssignTo: &ui.serverCB, MinSize: d.Size{Width: 280},
                                        OnCurrentIndexChanged: func() { ui.onServerChanged() }},
                        }},
                        d.CheckBox{AssignTo: &ui.chkProxy, Text: "پروکسی خودکار ویندوز (برای مرورگرها)", Checked: true,
                                OnCheckedChanged: func() { ui.onSysProxyChanged() }},
                        d.Label{AssignTo: &ui.trafficLbl, Text: "", TextColor: walk.RGB(90, 90, 90)},
                        d.GroupBox{Title: "گزارش", Layout: d.VBox{MarginsZero: true}, Children: []d.Widget{
                                d.TextEdit{AssignTo: &ui.logTE, ReadOnly: true, VScroll: true},
                        }},
                        d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
                                d.PushButton{Text: "خروج از برنامه", OnClicked: ui.exitApp},
                                d.HSpacer{},
                                d.Label{Text: "نسخه " + appVersion, TextColor: walk.RGB(140, 140, 140)},
                        }},
                },
        }).Create(); uerr != nil {
                return false
        }

        if ui.icoApp != nil {
                _ = ui.mw.SetIcon(ui.icoApp)
        }

        // closing the window hides it to the tray (v2ray-style); exit is via the
        // dedicated button or the tray menu, both instant
        ui.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
                *canceled = true
                ui.mw.Hide()
        })

        ui.setupTray()

        // 1-second UI refresh loop: state, traffic, server list, log tail
        go func() {
                t := time.NewTicker(1 * time.Second)
                defer t.Stop()
                for range t.C {
                        ui.refresh()
                }
        }()

        ui.refresh()
        ui.mw.Show()
        ui.mw.Run() // blocks until exitApp() hard-exits the process

        // only reached if walk quit on its own (should not happen)
        core.ShutdownQuick()
        os.Exit(0)
        return true
}

// ---------- tray ----------

func (ui *nativeUI) setupTray() {
        ni, err := walk.NewNotifyIcon(ui.mw)
        if err != nil {
                return
        }
        ui.ni = ni
        if ui.icoOff != nil {
                _ = ni.SetIcon(ui.icoOff)
        }
        _ = ni.SetToolTip("FoxyVPN — قطع است")
        ni.MouseDown().Attach(func(x, y int, btn walk.MouseButton) {
                if btn == walk.LeftButton {
                        ui.showWindow()
                }
        })
        menu := ni.ContextMenu()
        aOpen := walk.NewAction()
        _ = aOpen.SetText("باز کردن پنل")
        aOpen.Triggered().Attach(func() { ui.showWindow() })
        menu.Actions().Add(aOpen)

        ui.aToggle = walk.NewAction()
        _ = ui.aToggle.SetText("اتصال")
        ui.aToggle.Triggered().Attach(func() { ui.onToggle() })
        menu.Actions().Add(ui.aToggle)

        aExit := walk.NewAction()
        _ = aExit.SetText("خروج")
        aExit.Triggered().Attach(ui.exitApp)
        menu.Actions().Add(aExit)

        _ = ni.SetVisible(true)
}

func (ui *nativeUI) showWindow() {
        win.ShowWindow(ui.mw.Handle(), win.SW_RESTORE)
        ui.mw.Show()
        win.SetForegroundWindow(ui.mw.Handle())
}

func (ui *nativeUI) exitApp() {
        if ui.ni != nil {
                _ = ui.ni.SetVisible(false) // don't leave a ghost icon
        }
        ui.core.ShutdownQuick()
        os.Exit(0)
}

// ---------- actions ----------

func (ui *nativeUI) onToggle() {
        snap := ui.core.Snapshot()
        switch snap.State {
        case StateConnected, StateConnecting:
                // Disconnect may wait on in-flight connect attempts; never block the
                // UI thread
                go ui.core.Disconnect()
        case StateNeedLogin, StateNeed2FA:
                openAccountDialog(ui)
        default:
                country, city := "", ""
                if idx := ui.serverCB.CurrentIndex(); idx >= 0 && idx < len(ui.serverOpts) {
                        country, city = ui.serverOpts[idx].Country, ui.serverOpts[idx].City
                }
                ui.core.Connect(country, city)
        }
}

func (ui *nativeUI) onServerChanged() {
        if ui.suppressCombo {
                return
        }
        idx := ui.serverCB.CurrentIndex()
        if idx >= 0 && idx < len(ui.serverOpts) {
                opt := ui.serverOpts[idx]
                ui.core.SetServerChoice(opt.Country, opt.City)
        }
}

func (ui *nativeUI) onSysProxyChanged() {
        if ui.suppressChk {
                return
        }
        ui.core.SetSysProxyEnabled(ui.chkProxy.Checked())
}

// ---------- periodic refresh ----------

func (ui *nativeUI) refresh() {
        snap := ui.core.Snapshot()
        opts := ui.core.ServerOptions()
        logs, seq := ui.core.RecentLogs(ui.logSeq)

        ui.mw.Synchronize(func() {
                ui.applyState(snap)

                if len(opts) != len(ui.serverOpts) {
                        ui.rebuildCombo(opts, snap)
                }
                if len(logs) > 0 {
                        for _, ln := range logs {
                                ui.logLines = append(ui.logLines, fmt.Sprintf("%02d:%02d:%02d [%s] %s",
                                        ln.T.Hour(), ln.T.Minute(), ln.T.Second(), ln.L, ln.M))
                        }
                        if len(ui.logLines) > 250 {
                                ui.logLines = ui.logLines[len(ui.logLines)-250:]
                        }
                        ui.logTE.SetText(strings.Join(ui.logLines, "\r\n"))
                }
                ui.logSeq = seq
        })
}

func (ui *nativeUI) applyState(snap Snapshot) {
        var status string
        var color walk.Color
        var btnText string
        switch snap.State {
        case StateNeedLogin:
                status, color, btnText = "وارد نشده‌اید", walk.RGB(120, 120, 120), "ورود به حساب"
        case StateNeed2FA:
                status, color, btnText = "کد تایید ایمیل لازم است", walk.RGB(190, 120, 0), "ورود با کد تایید"
        case StateConnecting:
                status, color, btnText = "در حال اتصال…", walk.RGB(190, 120, 0), "لغو"
        case StateConnected:
                status, color, btnText = "وصل است ✓", walk.RGB(0, 130, 50), "قطع اتصال"
        default:
                status, color, btnText = "قطع است", walk.RGB(160, 40, 40), "اتصال"
        }
        ui.statusLbl.SetText(status)
        ui.statusLbl.SetTextColor(color)
        ui.btnToggle.SetText(btnText)
        if ui.aToggle != nil {
                ui.aToggle.SetText(btnText)
        }
        if ui.ni != nil {
                if snap.State == StateConnected && ui.icoOn != nil {
                        ui.ni.SetIcon(ui.icoOn)
                } else if ui.icoOff != nil {
                        ui.ni.SetIcon(ui.icoOff)
                }
                tooltip := "FoxyVPN — " + status
                if snap.ExitCountry != "" {
                        tooltip += " (" + snap.ExitCountry + ")"
                }
                ui.ni.SetToolTip(tooltip)
        }

        detail := ""
        if snap.State == StateConnected && snap.ExitIP != "" {
                detail = "IP خروجی: " + snap.ExitIP
                if snap.ExitCountry != "" {
                        detail += " (" + snap.ExitCountry + ")"
                }
        }
        if snap.StateMsg != "" {
                if detail != "" {
                        detail += "  ·  "
                }
                detail += faStateMessage(snap.StateMsg)
        }
        ui.detailLbl.SetText(detail)

        account := "حساب: —"
        if snap.Email != "" {
                account = "حساب: " + snap.Email
                if snap.Need2FA {
                        account += " (کد تایید لازم است)"
                }
        }
        ui.accountLbl.SetText(account)

        ui.trafficLbl.SetText(fmt.Sprintf("ترافیک: ↓ %s  ↑ %s     پورت‌ها: HTTP 127.0.0.1:%d  ·  SOCKS 127.0.0.1:%d",
                humanBytes(snap.DownBytes), humanBytes(snap.UpBytes), snap.HttpPort, snap.SocksPort))

        if ui.chkProxy.Checked() != snap.SysProxy {
                ui.suppressChk = true
                ui.chkProxy.SetChecked(snap.SysProxy)
                ui.suppressChk = false
        }
}

func (ui *nativeUI) rebuildCombo(opts []ServerOption, snap Snapshot) {
        ui.serverOpts = opts
        labels := make([]string, len(opts))
        for i, o := range opts {
                labels[i] = o.Label
        }
        ui.suppressCombo = true
        _ = ui.serverCB.SetModel(labels)
        // restore the persisted selection if it is still present
        idx := 0
        for i, o := range opts {
                if o.Country != "" && strings.EqualFold(o.Country, snap.Country) &&
                        strings.EqualFold(o.City, snap.City) {
                        idx = i
                        break
                }
        }
        _ = ui.serverCB.SetCurrentIndex(idx)
        ui.suppressCombo = false
}

// ---------- login / 2FA dialog ----------

func openAccountDialog(ui *nativeUI) {
        var dlg *walk.Dialog
        var emailEd, passEd, codeEd *walk.LineEdit
        var errLbl *walk.Label
        var acceptPB *walk.PushButton

        var busy int32
        _, _ = (d.Dialog{
                AssignTo:      &dlg,
                Title:         "ورود با حساب فایرفاکس",
                MinSize:       d.Size{Width: 370, Height: 260},
                DefaultButton: &acceptPB,
                Font:          d.Font{Family: "Tahoma", PointSize: 9},
                Layout:        d.VBox{Margins: d.Margins{Left: 14, Top: 12, Right: 14, Bottom: 12}, Spacing: 4},
                Children: []d.Widget{
                        d.Label{Text: "ایمیل فایرفاکس:"},
                        d.LineEdit{AssignTo: &emailEd, CueBanner: "you@example.com"},
                        d.VSpacer{Size: 2},
                        d.Label{Text: "رمز عبور:"},
                        d.LineEdit{AssignTo: &passEd, PasswordMode: true},
                        d.VSpacer{Size: 2},
                        d.Label{Text: "کد تایید ارسال‌شده به ایمیل (فقط وقتی از شما خواسته شد):"},
                        d.LineEdit{AssignTo: &codeEd},
                        d.Label{AssignTo: &errLbl, Text: "", TextColor: walk.RGB(170, 40, 40)},
                        d.VSpacer{Size: 4},
                        d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
                                d.PushButton{AssignTo: &acceptPB, Text: "ورود", OnClicked: func() {
                                        if !atomic.CompareAndSwapInt32(&busy, 0, 1) {
                                                return
                                        }
                                        email := emailEd.Text()
                                        pass := passEd.Text()
                                        code := codeEd.Text()
                                        core := ui.core
                                        go func() {
                                                var err error
                                                if strings.TrimSpace(code) != "" {
                                                        err = core.Verify2FA(strings.TrimSpace(code))
                                                } else {
                                                        err = core.Login(strings.TrimSpace(email), pass)
                                                }
                                                dlg.Synchronize(func() {
                                                        if err != nil {
                                                                errLbl.SetText(faError(err))
                                                                atomic.StoreInt32(&busy, 0)
                                                                return
                                                        }
                                                        dlg.Accept()
                                                })
                                        }()
                                }},
                                d.HSpacer{},
                                d.PushButton{Text: "خروج از حساب", OnClicked: func() {
                                        go func() { _ = ui.core.Logout() }()
                                        dlg.Accept()
                                }},
                                d.PushButton{Text: "انصراف", OnClicked: func() { dlg.Cancel() }},
                        }},
                },
        }).Run(ui.mw)
}

// ---------- helpers ----------

func loadWalkIcons(dataDir string) (app, on, off *walk.Icon) {
        dir := filepath.Join(dataDir, "icons")
        _ = os.MkdirAll(dir, 0o700)
        write := func(name string, data []byte) string {
                p := filepath.Join(dir, name)
                if _, statErr := os.Stat(p); statErr != nil {
                        _ = os.WriteFile(p, data, 0o600)
                }
                return p
        }
        app, _ = walk.NewIconFromFile(write("app.ico", iconApp))
        on, _ = walk.NewIconFromFile(write("on.ico", iconOn))
        off, _ = walk.NewIconFromFile(write("off.ico", iconOff))
        return app, on, off
}

// faStateMessage maps common engine messages to plain Persian for the UI.
func faStateMessage(msg string) string {
        m := strings.ToLower(msg)
        switch {
        case strings.Contains(m, "quota"):
                return "سهمیه رایگان ماهانه تمام شده است (ماه بعد شارژ می‌شود)"
        case strings.Contains(m, "sign in first"):
                return "ابتدا وارد حساب شوید"
        case strings.Contains(m, "server list"):
                return "دریافت لیست سرورها ممکن نشد (اینترنت را بررسی کنید)"
        case strings.Contains(m, "edge rejected connect"):
                return "سرور درخواست تونل را رد کرد — دوباره تلاش کنید"
        case strings.Contains(m, "proxy pass"):
                return "خطای احراز هویت سرویس گاردین"
        case strings.Contains(m, "traffic verification"):
                return "تونل ساخته شد ولی ترافیک عبور نکرد — سرور دیگری امتحان می‌شود"
        case strings.Contains(m, "tls"):
                return "اتصال امن به سرور برقرار نشد (احتمال اختلال فیلترینگ)"
        case strings.Contains(m, "timeout"), strings.Contains(m, "timed out"):
                return "مهلت اتصال تمام شد — دوباره تلاش می‌کنیم"
        default:
                return msg
        }
}

func faError(err error) string {
        if err == nil {
                return ""
        }
        m := strings.ToLower(err.Error())
        switch {
        case strings.Contains(m, "errno=103"), strings.Contains(m, "errno=126"),
                strings.Contains(m, "email or password"), strings.Contains(m, "incorrect"):
                return "ایمیل یا رمز عبور اشتباه است"
        case strings.Contains(m, "errno=107"):
                return "حساب نیاز به تایید ایمیل دارد؛ کد تایید را وارد کنید"
        case strings.Contains(m, "errno=121"), strings.Contains(m, "errno=122"):
                return "تلاش بیش از حد؛ چند دقیقه بعد دوباره امتحان کنید"
        case strings.Contains(m, "quota"):
                return "سهمیه رایگان ماهانه تمام شده است"
        case strings.Contains(m, "verification code"), strings.Contains(m, "verify"):
                return "کد تایید قبول نشد؛ کد جدید را وارد کنید"
        case strings.Contains(m, "disconnect before switching"):
                return "ابتدا اتصال را قطع کنید"
        case strings.Contains(m, "network"), strings.Contains(m, "timeout"), strings.Contains(m, "timed out"):
                return "خطای شبکه؛ اتصال اینترنت را بررسی کنید"
        default:
                return err.Error()
        }
}
