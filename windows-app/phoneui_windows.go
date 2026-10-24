//go:build windows

package main

// Phone-style Windows UI: a small fixed-size vertical window that replicates
// the Android FoxyVPN app one-to-one — pastel gradient background, account
// card with usage bar, the big dark power-plug button, stat cards, bottom
// navigation (خانه / سرورها / تنظیمات) and an in-window Firefox login page.
// Pure GDI custom painting on a walk CustomWidget: no WebView2, no browser.
// Same core, same tray, same single-instance behavior as the classic UI.

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"
	d "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

// ---------- pages ----------

const (
	pgHome = iota
	pgServers
	pgSettings
	pgLogin
)

// ---------- palette (mirrors android ui/theme/Palette.kt) ----------

type phonePalette struct {
	name       string
	top, bot   walk.Color
	accent     walk.Color
	accentDeep walk.Color
}

var phonePalettes = []phonePalette{
	{"mint", hexC(0xE7F8EF), hexC(0xF4FBF7), hexC(0x27C07D), hexC(0x128A56)},
	{"rose", hexC(0xFDE8EC), hexC(0xFEF4F6), hexC(0xE9486C), hexC(0xB72749)},
	{"sky", hexC(0xE3F0FD), hexC(0xF2F8FE), hexC(0x2E9BF0), hexC(0x1668B4)},
}

// shared ink colors (from the Android theme)
const (
	colInk    = 0x20303C
	colSub    = 0x7A8794
	colFaint  = 0x98A2AE
	colWhite  = 0xFFFFFF
	colDark   = 0x1B2A38
	colTrack  = 0xE3E8EF
	colPlug   = 0xAEB8C2
	colNavTxt = 0x8A97A5
	colRed    = 0xC0392B
	colAmber  = 0xB57A00
	colBorder = 0xE3E8EF
)

func hexC(v uint32) walk.Color { // 0xRRGGBB → GDI COLORREF 0x00BBGGRR
	return walk.Color(((v & 0xFF) << 16) | (v & 0xFF00) | ((v >> 16) & 0xFF))
}

func blendC(a, b walk.Color, t float64) walk.Color {
	mix := func(x, y byte) byte { return byte(int(x) + int(float64(int(y)-int(x))*t)) }
	return walk.RGB(mix(a.R(), b.R()), mix(a.G(), b.G()), mix(a.B(), b.B()))
}

const dtRTL = walk.DrawTextFormat(win.DT_RTLREADING)

// ---------- hit-test layout ----------

type phoneRects struct {
	// home
	bolt, power, pill                  walk.Rectangle
	cardStats1, cardStats2, cardStats3 walk.Rectangle
	navHome, navServers, navSettings   walk.Rectangle
	// servers / settings common
	back        walk.Rectangle
	scrollTrack walk.Rectangle
	rows        []walk.Rectangle
	// settings rows (indices meaningful only while page==pgSettings)
	setProxy, setAccount, setLogout, setExit walk.Rectangle
	// login
	btnLogin, backLogin walk.Rectangle
}

type phoneUI struct {
	core   *Core
	mw     *walk.MainWindow
	ni     *walk.NotifyIcon
	holder *walk.Composite
	canvas *walk.CustomWidget

	icoApp, icoOn, icoOff *walk.Icon
	aToggle               *walk.Action

	pal  phonePalette
	page int

	r       phoneRects
	selIdx  int
	scrollY int
	drag    bool
	dragY   int

	emailEd, passEd, codeEd *walk.LineEdit
	loginErr                string
	loginBusy               int32

	snap    Snapshot
	opts    []ServerOption
	logSeq  int
	logTail []string

	// cached fonts
	fTitle, fStatus, fH2, fName, fBig, fMed, fMed2, fSmall, fTiny, fNav *walk.Font

	// servers page: parallel to ui.r.rows — model index of each visible row
	rowIdx []int
}

// startPhoneWindow blocks on the Win32 message loop until the app exits.
// Returns false only if the window could not be created (caller falls back to
// the classic UI, then the browser panel).
func startPhoneWindow(core *Core, panelURL, dataDir string) bool {
	runtime.LockOSThread()

	ui := &phoneUI{core: core}
	ui.pal = phonePalettes[rand.Intn(len(phonePalettes))]
	ui.icoApp, ui.icoOn, ui.icoOff = loadWalkIcons(dataDir)
	ui.selIdx = 0

	if uerr := (d.MainWindow{
		AssignTo: &ui.mw,
		Title:    "FoxyVPN",
		MinSize:  d.Size{Width: 375, Height: 800},
		MaxSize:  d.Size{Width: 375, Height: 800},
		Font:     d.Font{Family: "Tahoma", PointSize: 9},
		Layout:   d.VBox{MarginsZero: true, Spacing: 0},
		Children: []d.Widget{
			d.Composite{
				AssignTo:      &ui.holder,
				Layout:        nil, // absolute placement: canvas + overlay login fields
				OnSizeChanged: func() { ui.reposition() },
				Children: []d.Widget{
					d.CustomWidget{
						AssignTo:            &ui.canvas,
						PaintPixels:         ui.paint,
						PaintMode:           d.PaintBuffered,
						ClearsBackground:    true,
						InvalidatesOnResize: true,
						OnMouseDown:         ui.onDown,
						OnMouseUp:           ui.onUp,
						OnMouseMove:         ui.onMove,
					},
					d.LineEdit{AssignTo: &ui.emailEd, Visible: false, CueBanner: "ایمیل فایرفاکس",
						Font: d.Font{Family: "Tahoma", PointSize: 10}},
					d.LineEdit{AssignTo: &ui.passEd, Visible: false, PasswordMode: true, CueBanner: "رمز عبور",
						Font: d.Font{Family: "Tahoma", PointSize: 10}},
					d.LineEdit{AssignTo: &ui.codeEd, Visible: false, CueBanner: "کد تایید ایمیل (فقط اگر خواسته شد)",
						Font: d.Font{Family: "Tahoma", PointSize: 10}},
				},
			},
		},
	}).Create(); uerr != nil {
		return false
	}

	if ui.icoApp != nil {
		_ = ui.mw.SetIcon(ui.icoApp)
	}

	// closing the window hides it to the tray (v2ray-style); exit via tray menu
	ui.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		*canceled = true
		ui.mw.Hide()
	})

	ui.setupTray()

	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		for range t.C {
			ui.refresh()
		}
	}()

	ui.refresh()
	ui.reposition()
	ui.mw.Show()
	ui.mw.Run()

	core.ShutdownQuick()
	os.Exit(0)
	return true
}

// ---------- absolute placement (canvas + login LineEdits) ----------

func (ui *phoneUI) reposition() {
	if ui.holder == nil || ui.canvas == nil {
		return
	}
	cb := ui.holder.ClientBounds()
	_ = ui.canvas.SetBounds(cb)
	ui.placeLoginFields(cb)
	ui.canvas.Invalidate()
}

func (ui *phoneUI) placeLoginFields(cb walk.Rectangle) {
	if ui.emailEd == nil || ui.passEd == nil || ui.codeEd == nil {
		return
	}
	show := ui.page == pgLogin
	if !show {
		ui.emailEd.SetVisible(false)
		ui.passEd.SetVisible(false)
		ui.codeEd.SetVisible(false)
		return
	}
	u := float64(cb.Width) / 375.0
	px := func(v int) int { return int(float64(v) * u) }
	fieldW := cb.Width - px(24)*2
	fields := []struct {
		ed *walk.LineEdit
		y  int
	}{{ui.emailEd, 118}, {ui.passEd, 170}, {ui.codeEd, 222}}
	for _, f := range fields {
		_ = f.ed.SetBounds(walk.Rectangle{X: cb.X + px(24), Y: cb.Y + px(f.y), Width: fieldW, Height: px(42)})
		f.ed.SetVisible(true)
	}
	if ui.snap.Need2FA {
		_ = ui.codeEd.SetText("")
		_ = ui.codeEd.SetFocus()
	}
}

// ---------- tray ----------

func (ui *phoneUI) setupTray() {
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
	_ = aOpen.SetText("باز کردن برنامه")
	aOpen.Triggered().Attach(func() { ui.showWindow() })
	menu.Actions().Add(aOpen)

	ui.aToggle = walk.NewAction()
	_ = ui.aToggle.SetText("اتصال")
	ui.aToggle.Triggered().Attach(func() { ui.onPower() })
	menu.Actions().Add(ui.aToggle)

	aExit := walk.NewAction()
	_ = aExit.SetText("خروج")
	aExit.Triggered().Attach(ui.exitApp)
	menu.Actions().Add(aExit)

	_ = ni.SetVisible(true)
}

func (ui *phoneUI) showWindow() {
	win.ShowWindow(ui.mw.Handle(), win.SW_RESTORE)
	ui.mw.Show()
	win.SetForegroundWindow(ui.mw.Handle())
}

func (ui *phoneUI) exitApp() {
	if ui.ni != nil {
		_ = ui.ni.SetVisible(false)
	}
	ui.core.ShutdownQuick()
	os.Exit(0)
}

// ---------- actions ----------

func (ui *phoneUI) setPage(p int) {
	ui.page = p
	if p != pgLogin {
		ui.loginErr = ""
	}
	cb := ui.holder.ClientBounds()
	ui.placeLoginFields(cb)
	ui.canvas.Invalidate()
}

func (ui *phoneUI) onPower() {
	s := ui.snap
	switch {
	case s.State == StateConnected || s.State == StateConnecting:
		go ui.core.Disconnect()
	case s.State == StateNeedLogin || s.State == StateNeed2FA:
		ui.setPage(pgLogin)
	default:
		country, city := "", ""
		if ui.selIdx >= 0 && ui.selIdx < len(ui.opts) {
			country, city = ui.opts[ui.selIdx].Country, ui.opts[ui.selIdx].City
		}
		go ui.core.Connect(country, city)
	}
}

func (ui *phoneUI) onLoginClick() {
	if !atomic.CompareAndSwapInt32(&ui.loginBusy, 0, 1) {
		return
	}
	email := strings.TrimSpace(ui.emailEd.Text())
	pass := ui.passEd.Text()
	code := strings.TrimSpace(ui.codeEd.Text())
	core := ui.core
	go func() {
		var err error
		if code != "" {
			err = core.Verify2FA(code)
		} else {
			err = core.Login(email, pass)
		}
		ui.mw.Synchronize(func() {
			atomic.StoreInt32(&ui.loginBusy, 0)
			if err != nil {
				ui.loginErr = faError(err)
				if strings.Contains(strings.ToLower(err.Error()), "verification") ||
					strings.Contains(strings.ToLower(err.Error()), "verify") ||
					strings.Contains(err.Error(), "errno=107") {
					ui.loginErr += " — کد را در کادر سوم وارد کنید"
				}
			} else {
				ui.loginErr = ""
				ui.emailEd.SetText("")
				ui.passEd.SetText("")
				ui.codeEd.SetText("")
				ui.setPage(pgHome)
			}
			ui.canvas.Invalidate()
		})
	}()
}

// ---------- 1-second refresh ----------

func (ui *phoneUI) refresh() {
	snap := ui.core.Snapshot()
	opts := ui.core.ServerOptions()
	logs, seq := ui.core.RecentLogs(ui.logSeq)

	ui.mw.Synchronize(func() {
		ui.snap = snap
		ui.opts = opts
		// selection sync (like rebuildCombo in the classic UI)
		ui.selIdx = 0
		for i, o := range ui.opts {
			if o.Country != "" && strings.EqualFold(o.Country, snap.Country) &&
				strings.EqualFold(o.City, snap.City) {
				ui.selIdx = i
				break
			}
		}
		if len(logs) > 0 {
			for _, ln := range logs {
				ui.logTail = append(ui.logTail, fmt.Sprintf("%02d:%02d:%02d [%s] %s",
					ln.T.Hour(), ln.T.Minute(), ln.T.Second(), ln.L, ln.M))
			}
			if len(ui.logTail) > 160 {
				ui.logTail = ui.logTail[len(ui.logTail)-160:]
			}
		}
		ui.logSeq = seq

		if ui.ni != nil {
			if snap.State == StateConnected && ui.icoOn != nil {
				_ = ui.ni.SetIcon(ui.icoOn)
			} else if ui.icoOff != nil {
				_ = ui.ni.SetIcon(ui.icoOff)
			}
			tt := "FoxyVPN — " + phoneStatusText(snap)
			if snap.ExitCountry != "" {
				tt += " (" + snap.ExitCountry + ")"
			}
			_ = ui.ni.SetToolTip(tt)
		}
		if ui.aToggle != nil {
			_ = ui.aToggle.SetText(phoneBtnText(snap))
		}
		ui.canvas.Invalidate()
	})
}

func phoneStatusText(s Snapshot) string {
	switch s.State {
	case StateNeedLogin:
		return "وارد نشده‌اید"
	case StateNeed2FA:
		return "کد تایید لازم است"
	case StateConnecting:
		return "در حال اتصال…"
	case StateConnected:
		return "وصل است ✓"
	default:
		return "قطع است"
	}
}

func phoneBtnText(s Snapshot) string {
	switch s.State {
	case StateNeedLogin, StateNeed2FA:
		return "ورود به حساب"
	case StateConnecting:
		return "لغو"
	case StateConnected:
		return "قطع اتصال"
	default:
		return "اتصال"
	}
}

// ---------- painting ----------

func (ui *phoneUI) px3q(px int) int { return px * 3 / 4 }

func (ui *phoneUI) ensureFonts() {
	if ui.fTitle != nil {
		return
	}
	mk := func(px int, bold bool) *walk.Font {
		st := walk.FontStyle(0)
		if bold {
			st = walk.FontBold
		}
		f, _ := walk.NewFont("Tahoma", ui.px3q(px), st)
		return f
	}
	ui.fTitle = mk(21, true)
	ui.fStatus = mk(20, true)
	ui.fH2 = mk(18, true)
	ui.fName = mk(15, true)
	ui.fBig = mk(15, false)
	ui.fMed = mk(13, false)
	ui.fMed2 = mk(12, false)
	ui.fSmall = mk(11, false)
	ui.fTiny = mk(10, false)
	ui.fNav = mk(11, false)
}

func (ui *phoneUI) paint(c *walk.Canvas, updateBounds walk.Rectangle) error {
	ui.ensureFonts()
	b := ui.canvas.Bounds()
	w, h := b.Width, b.Height
	if w <= 0 || h <= 0 || ui.fTitle == nil {
		return nil
	}
	u := float64(w) / 375.0
	ui.layout(w, h, u)
	_ = c.GradientFillRectanglePixels(ui.pal.top, ui.pal.bot, walk.Vertical, b)
	switch ui.page {
	case pgHome:
		ui.paintHome(c, w, h, u)
	case pgServers:
		ui.paintServers(c, w, h, u)
	case pgSettings:
		ui.paintSettings(c, w, h, u)
	case pgLogin:
		ui.paintLogin(c, w, h, u)
	}
	return nil
}

func (ui *phoneUI) layout(w, h int, u float64) {
	px := func(v int) int { return int(float64(v) * u) }
	m := px(18)
	ui.r = phoneRects{}
	// header bolt
	ui.r.bolt = walk.Rectangle{X: m, Y: px(16), Width: px(20), Height: px(26)}
	// home widgets
	cardY, cardH := px(52), px(126)
	cx := w / 2
	cy := cardY + cardH + px(137)
	r := px(80)
	ui.r.power = walk.Rectangle{X: cx - r, Y: cy - r, Width: 2 * r, Height: 2 * r}
	pillW := px(240)
	ui.r.pill = walk.Rectangle{X: cx - pillW/2, Y: cy + r + px(81), Width: pillW, Height: px(44)}
	statsY, statsH := ui.r.pill.Y+px(58), px(76)
	gap := px(10)
	sw := (w - 2*m - 2*gap) / 3
	ui.r.cardStats1 = walk.Rectangle{X: w - m - sw, Y: statsY, Width: sw, Height: statsH}
	ui.r.cardStats2 = walk.Rectangle{X: w - m - 2*sw - gap, Y: statsY, Width: sw, Height: statsH}
	ui.r.cardStats3 = walk.Rectangle{X: m, Y: statsY, Width: sw, Height: statsH}
	// bottom nav
	navY := h - px(58)
	ui.r.navHome = walk.Rectangle{X: cx - px(56), Y: navY, Width: px(112), Height: px(58)}
	ui.r.navServers = walk.Rectangle{X: cx - px(150), Y: navY, Width: px(80), Height: px(58)}
	ui.r.navSettings = walk.Rectangle{X: cx + px(70), Y: navY, Width: px(80), Height: px(58)}
	// back button (servers/settings/login) — RTL: at the right edge
	ui.r.back = walk.Rectangle{X: w - m - px(44), Y: px(8), Width: px(44), Height: px(44)}
	// servers list geometry
	ui.r.scrollTrack = walk.Rectangle{X: w - px(6), Y: px(58), Width: px(4), Height: h - px(66) - px(58)}
	// login
	ui.r.btnLogin = walk.Rectangle{X: m, Y: px(318), Width: w - 2*m, Height: px(46)}
	ui.r.backLogin = walk.Rectangle{X: w - m - px(96), Y: px(8), Width: px(96), Height: px(40)}

	// server rows (visible slice)
	rowH, rowGap := px(52), px(8)
	listY, listH := px(58), h-px(66)-px(58)
	ui.r.rows = ui.r.rows[:0]
	ui.rowIdx = ui.rowIdx[:0]
	if len(ui.opts) > 0 {
		pitch := rowH + rowGap
		content := len(ui.opts)*pitch + px(4)
		maxScroll := content - listH
		if maxScroll < 0 {
			maxScroll = 0
		}
		if ui.scrollY > maxScroll {
			ui.scrollY = maxScroll
		}
		if ui.scrollY < 0 {
			ui.scrollY = 0
		}
		for i := 0; i < len(ui.opts); i++ {
			y := listY + px(4) + i*pitch - ui.scrollY
			if y+rowH < listY {
				continue
			}
			if y > listY+listH {
				break
			}
			ui.r.rows = append(ui.r.rows, walk.Rectangle{X: m, Y: y, Width: w - 2*m - px(10), Height: rowH})
			ui.rowIdx = append(ui.rowIdx, i)
		}
	}
	// settings rows
	sy := px(58)
	ui.r.setProxy = walk.Rectangle{X: m, Y: sy, Width: w - 2*m, Height: px(54)}
	sy += px(62)
	ui.r.setAccount = walk.Rectangle{X: m, Y: sy, Width: w - 2*m, Height: px(54)}
	sy += px(62)
	if ui.snap.Email != "" {
		ui.r.setLogout = walk.Rectangle{X: m, Y: sy, Width: w - 2*m, Height: px(54)}
		sy += px(62)
	} else {
		ui.r.setLogout = walk.Rectangle{}
	}
	ui.r.setExit = walk.Rectangle{X: m, Y: sy, Width: w - 2*m, Height: px(54)}
	sy += px(54) + px(10)
	_ = sy
}

// ---------- drawing helpers ----------

func (ui *phoneUI) fillR(c *walk.Canvas, r walk.Rectangle, col walk.Color) {
	br, err := walk.NewSolidColorBrush(col)
	if err != nil {
		return
	}
	defer br.Dispose()
	_ = c.FillRectanglePixels(br, r)
}

func (ui *phoneUI) fillRound(c *walk.Canvas, r walk.Rectangle, rad int, col walk.Color) {
	br, err := walk.NewSolidColorBrush(col)
	if err != nil {
		return
	}
	defer br.Dispose()
	_ = c.FillRoundedRectanglePixels(br, r, walk.Size{Width: rad * 2, Height: rad * 2})
}

func (ui *phoneUI) strokeRound(c *walk.Canvas, r walk.Rectangle, rad, wpx int, col walk.Color) {
	br, err := walk.NewSolidColorBrush(col)
	if err != nil {
		return
	}
	defer br.Dispose()
	pen, err := walk.NewGeometricPen(walk.PenSolid, wpx, br)
	if err != nil {
		return
	}
	defer pen.Dispose()
	_ = c.DrawRoundedRectanglePixels(pen, r, walk.Size{Width: rad * 2, Height: rad * 2})
}

func (ui *phoneUI) fillEll(c *walk.Canvas, r walk.Rectangle, col walk.Color) {
	br, err := walk.NewSolidColorBrush(col)
	if err != nil {
		return
	}
	defer br.Dispose()
	_ = c.FillEllipsePixels(br, r)
}

func (ui *phoneUI) strokeEll(c *walk.Canvas, r walk.Rectangle, wpx int, col walk.Color) {
	br, err := walk.NewSolidColorBrush(col)
	if err != nil {
		return
	}
	defer br.Dispose()
	pen, err := walk.NewGeometricPen(walk.PenSolid, wpx, br)
	if err != nil {
		return
	}
	defer pen.Dispose()
	_ = c.DrawEllipsePixels(pen, r)
}

func (ui *phoneUI) strokePts(c *walk.Canvas, pts []walk.Point, wpx int, col walk.Color) {
	br, err := walk.NewSolidColorBrush(col)
	if err != nil {
		return
	}
	defer br.Dispose()
	pen, err := walk.NewGeometricPen(walk.PenSolid, wpx, br)
	if err != nil {
		return
	}
	defer pen.Dispose()
	_ = c.DrawPolylinePixels(pen, pts)
}

func (ui *phoneUI) txtR(c *walk.Canvas, s string, r walk.Rectangle, f *walk.Font, col walk.Color) {
	_ = c.DrawTextPixels(s, f, col, r, walk.TextSingleLine|walk.TextVCenter|walk.TextRight|dtRTL)
}

func (ui *phoneUI) txtC(c *walk.Canvas, s string, r walk.Rectangle, f *walk.Font, col walk.Color) {
	_ = c.DrawTextPixels(s, f, col, r, walk.TextSingleLine|walk.TextVCenter|walk.TextCenter)
}

func (ui *phoneUI) txtCR(c *walk.Canvas, s string, r walk.Rectangle, f *walk.Font, col walk.Color) {
	_ = c.DrawTextPixels(s, f, col, r, walk.TextSingleLine|walk.TextVCenter|walk.TextCenter|dtRTL)
}

func (ui *phoneUI) txtL(c *walk.Canvas, s string, r walk.Rectangle, f *walk.Font, col walk.Color) {
	_ = c.DrawTextPixels(s, f, col, r, walk.TextSingleLine|walk.TextVCenter|walk.TextLeft)
}

func (ui *phoneUI) txtWrap(c *walk.Canvas, s string, r walk.Rectangle, f *walk.Font, col walk.Color) {
	_ = c.DrawTextPixels(s, f, col, r, walk.TextWordbreak|walk.TextVCenter|dtRTL)
}

// ---------- tiny vector icons (outlined, material-ish) ----------

func (ui *phoneUI) iconBolt(c *walk.Canvas, cx, cy, s int, col walk.Color) {
	ui.strokePts(c, []walk.Point{
		{X: cx + s*4/10, Y: cy - s/2},
		{X: cx - s*2/10, Y: cy + s/10},
		{X: cx + s*1/10, Y: cy + s/10},
		{X: cx - s*4/10, Y: cy + s/2},
	}, s/5+1, col)
}

func (ui *phoneUI) iconGear(c *walk.Canvas, cx, cy, r int, col, bg walk.Color) {
	ui.fillEll(c, walk.Rectangle{X: cx - r*6/10, Y: cy - r*6/10, Width: r * 12 / 10, Height: r * 12 / 10}, col)
	for i := 0; i < 6; i++ {
		ang := float64(i) * 1.0472
		dx, dy := float64(r)*0.72, float64(r)*1.18
		x1 := cx + int(dx*sinA(ang))
		y1 := cy - int(dy*cosA(ang))
		x2 := cx + int(dx*sinA(ang)*1.15)
		y2 := cy - int(dy*cosA(ang)*1.15)
		ui.strokePts(c, []walk.Point{{X: x1, Y: y1}, {X: x2, Y: y2}}, r/3+1, col)
	}
	ui.fillEll(c, walk.Rectangle{X: cx - r/4, Y: cy - r/4, Width: r / 2, Height: r / 2}, bg)
}

func (ui *phoneUI) iconHome(c *walk.Canvas, cx, cy, s int, col, bg walk.Color) {
	ui.fillRound(c, walk.Rectangle{X: cx - s*4/10, Y: cy - s/10, Width: s * 8 / 10, Height: s * 55 / 100}, s/8, col)
	ui.strokePts(c, []walk.Point{
		{X: cx - s*6/10, Y: cy - s/10},
		{X: cx, Y: cy - s*6/10},
		{X: cx + s*6/10, Y: cy - s/10},
	}, s/6+1, col)
	ui.fillR(c, walk.Rectangle{X: cx - s/8, Y: cy + s/6, Width: s / 4, Height: s * 28 / 100}, bg)
}

func (ui *phoneUI) iconGlobe(c *walk.Canvas, cx, cy, r int, col walk.Color) {
	ui.strokeEll(c, walk.Rectangle{X: cx - r, Y: cy - r, Width: 2 * r, Height: 2 * r}, r/5+1, col)
	ui.strokePts(c, []walk.Point{{X: cx - r, Y: cy}, {X: cx + r, Y: cy}}, r/5+1, col)
	ui.strokeEll(c, walk.Rectangle{X: cx - r*4/10, Y: cy - r, Width: r * 8 / 10, Height: 2 * r}, r/8+1, col)
}

func (ui *phoneUI) iconPlug(c *walk.Canvas, cx, cy, u float64, col walk.Color) {
	px := func(v int) int { return int(float64(v) * u) }
	cx1, cy1 := int(cx), int(cy)
	// prongs
	ui.fillR(c, walk.Rectangle{X: cx1 - px(11), Y: cy1 - px(34), Width: px(7), Height: px(15)}, col)
	ui.fillR(c, walk.Rectangle{X: cx1 + px(4), Y: cy1 - px(34), Width: px(7), Height: px(15)}, col)
	// body
	ui.fillRound(c, walk.Rectangle{X: cx1 - px(16), Y: cy1 - px(21), Width: px(32), Height: px(40)}, px(8), col)
	// neck
	ui.fillR(c, walk.Rectangle{X: cx1 - px(7), Y: cy1 + px(19), Width: px(14), Height: px(9)}, col)
}

func (ui *phoneUI) iconCheck(c *walk.Canvas, x, y int, col walk.Color) {
	ui.strokePts(c, []walk.Point{{X: x, Y: y + 4}, {X: x + 6, Y: y + 10}, {X: x + 16, Y: y - 4}}, 3, col)
}

func (ui *phoneUI) iconBack(c *walk.Canvas, cx, cy, s int, col walk.Color) {
	ui.strokePts(c, []walk.Point{
		{X: cx - s*3/10, Y: cy - s/2},
		{X: cx + s*3/10, Y: cy},
		{X: cx - s*3/10, Y: cy + s/2},
	}, s/4+1, col)
}

func sinA(a float64) float64 { return float64(math.Sin(a)) }
func cosA(a float64) float64 { return float64(math.Cos(a)) }

// ---------- home page ----------

func (ui *phoneUI) paintHome(c *walk.Canvas, w, h int, u float64) {
	px := func(v int) int { return int(float64(v) * u) }
	m := px(18)

	// header
	ui.txtR(c, "FoxyVPN", walk.Rectangle{X: w - m - px(150), Y: px(12), Width: px(150), Height: px(32)}, ui.fTitle, hexC(colInk))
	ui.txtR(c, "اینترنت آزاد", walk.Rectangle{X: w - m - px(262), Y: px(20), Width: px(108), Height: px(20)}, ui.fSmall, hexC(colSub))
	ui.txtR(c, "v"+appVersion, walk.Rectangle{X: w - m - px(330), Y: px(24), Width: px(64), Height: px(16)}, ui.fTiny, hexC(colFaint))
	ui.iconBolt(c, m+px(10), px(29), px(22), ui.pal.accent)

	// account card
	card := walk.Rectangle{X: m, Y: px(52), Width: w - 2*m, Height: px(126)}
	ui.fillRound(c, card, px(20), hexC(colWhite))
	av := walk.Rectangle{X: card.X + card.Width - px(64), Y: card.Y + px(16), Width: px(40), Height: px(40)}
	name := "کاربر"
	email := ui.snap.Email
	letter := "؟"
	if email != "" {
		if i := strings.Index(email, "@"); i > 0 {
			name = email[:i]
		} else {
			name = email
		}
		letter = strings.ToUpper(name[:1])
	}
	if letter != "؟" {
		ui.fillEll(c, av, ui.pal.accent)
		ui.txtC(c, letter, av, ui.fName, hexC(colWhite))
	} else {
		ui.fillEll(c, av, hexC(colTrack))
		ui.txtC(c, letter, av, ui.fName, hexC(colSub))
	}
	tx := walk.Rectangle{X: card.X + px(14), Y: card.Y + px(16), Width: card.Width - px(92), Height: px(24)}
	ui.txtR(c, name, tx, ui.fName, hexC(colInk))
	line2 := tx
	line2.Y += px(26)
	if email != "" {
		l2 := "اشتراک رایگان گاردین فعال"
		if ui.snap.State == StateConnected {
			l2 += " ✓"
		}
		ui.txtR(c, l2, line2, ui.fMed2, ui.pal.accentDeep)
	} else {
		ui.txtR(c, "وارد حساب فایرفاکس نشده‌اید", line2, ui.fMed2, hexC(colFaint))
	}
	line3 := line2
	line3.Y += px(22)
	ratio := quotaRatio(ui.snap)
	remainTxt, usedTxt := "—", "—"
	if ratio >= 0 {
		maxB, remB := *ui.snap.QuotaMax, *ui.snap.QuotaRemain
		remainTxt = humanBytes(remB)
		usedTxt = humanBytes(maxB - remB)
	} else if email != "" {
		ui.txtR(c, "سهمیه پس از اولین اتصال نمایش داده می‌شود", line3, ui.fTiny, hexC(colFaint))
	} else {
		ui.txtR(c, "برای مشاهده سهمیه وارد شوید", line3, ui.fTiny, hexC(colFaint))
	}
	if ratio >= 0 {
		ui.txtR(c, "حجم باقی‌مانده:", line3, ui.fTiny, hexC(colSub))
		ui.txtL(c, remainTxt, walk.Rectangle{X: card.X + px(14), Y: line3.Y, Width: px(90), Height: line3.Height}, ui.fTiny, hexC(colInk))
	}
	// progress bar
	track := walk.Rectangle{X: card.X + px(14), Y: card.Y + px(88), Width: card.Width - px(28), Height: px(8)}
	ui.fillRound(c, track, px(4), hexC(colTrack))
	if ratio >= 0 {
		fw := int(float64(track.Width) * ratio)
		if fw < px(10) {
			fw = px(10)
		}
		ui.fillRound(c, walk.Rectangle{X: track.X + track.Width - fw, Y: track.Y, Width: fw, Height: track.Height}, px(4), ui.pal.accent)
	}
	cap := walk.Rectangle{X: card.X + px(14), Y: card.Y + px(102), Width: card.Width - px(28), Height: px(18)}
	ui.txtR(c, "مصرف شده", cap, ui.fTiny, hexC(colSub))
	if usedTxt != "—" {
		ui.txtL(c, usedTxt, cap, ui.fTiny, hexC(colInk))
	}

	// power button + rings
	pr := ui.r.power
	cx, cy := pr.X+pr.Width/2, pr.Y+pr.Height/2
	ringCol := hexC(colFaint)
	switch ui.snap.State {
	case StateConnected:
		ringCol = ui.pal.accent
	case StateConnecting:
		ringCol = hexC(colAmber)
	}
	ui.fillEll(c, inflate(pr, px(38)), blendC(ringCol, ui.pal.top, 0.86))
	ui.fillEll(c, inflate(pr, px(19)), blendC(ringCol, ui.pal.top, 0.72))
	ui.fillEll(c, pr, hexC(colDark))
	plugCol := hexC(colPlug)
	if ui.snap.State == StateConnected {
		plugCol = blendC(hexC(colWhite), ui.pal.accent, 0.25)
	}
	ui.iconPlug(c, float64(cx), float64(cy+px(2)), u, plugCol)

	// status + timer
	ui.txtC(c, phoneStatusText(ui.snap), walk.Rectangle{X: cx - px(130), Y: pr.Y + pr.Height + px(14), Width: px(260), Height: px(30)}, ui.fStatus, hexC(colInk))
	ui.txtC(c, elapsedText(ui.snap), walk.Rectangle{X: cx - px(130), Y: pr.Y + pr.Height + px(44), Width: px(260), Height: px(22)}, ui.fBig, hexC(colSub))

	// system proxy pill
	pill := ui.r.pill
	ui.fillRound(c, pill, px(22), hexC(colWhite))
	ui.strokeRound(c, pill, px(22), 1, hexC(colBorder))
	pillTxt := "پروکسی سیستم ویندوز: خاموش"
	if ui.snap.SysProxy {
		pillTxt = "پروکسی سیستم ویندوز: روشن"
	}
	ui.txtCR(c, pillTxt, walk.Rectangle{X: pill.X + px(30), Y: pill.Y, Width: pill.Width - px(38), Height: pill.Height}, ui.fMed, hexC(colInk))
	ui.iconBolt(c, pill.X+px(20), pill.Y+pill.Height/2, px(16), ui.pal.accent)

	// stat cards
	ui.statCard(c, ui.r.cardStats1, "مصرف این جلسه", humanBytes(ui.snap.UpBytes+ui.snap.DownBytes))
	ui.statCard(c, ui.r.cardStats2, "زمان اتصال", elapsedText(ui.snap))
	ui.statCard(c, ui.r.cardStats3, "سرور فعلی", ui.currentServerShort())

	// bottom nav
	ui.paintNav(c, w, h, u)
}

func (ui *phoneUI) statCard(c *walk.Canvas, r walk.Rectangle, label, value string) {
	ui.fillRound(c, r, px0(r.Height/5), hexC(colWhite))
	lab := walk.Rectangle{X: r.X + px0(8), Y: r.Y + px0(10), Width: r.Width - px0(16), Height: px0(18)}
	ui.txtCR(c, label, lab, ui.fTiny, hexC(colSub))
	val := walk.Rectangle{X: r.X + px0(6), Y: r.Y + px0(34), Width: r.Width - px0(12), Height: px0(26)}
	ui.txtC(c, value, val, ui.fName, hexC(colInk))
}

func px0(v int) int { return v }

func (ui *phoneUI) currentServerShort() string {
	if ui.snap.ExitCountry != "" {
		return ui.snap.ExitCountry
	}
	if ui.selIdx > 0 && ui.selIdx < len(ui.opts) {
		lab := ui.opts[ui.selIdx].Label
		if i := strings.Index(lab, " — "); i > 0 {
			return lab[:i]
		}
		return lab
	}
	return "خودکار"
}

func (ui *phoneUI) paintNav(c *walk.Canvas, w, h int, u float64) {
	nav := walk.Rectangle{X: 0, Y: ui.r.navHome.Y, Width: w, Height: h - ui.r.navHome.Y}
	ui.fillRound(c, walk.Rectangle{X: nav.X, Y: nav.Y - px0(20), Width: nav.Width, Height: nav.Height + px0(20)}, px0(20), hexC(colWhite))
	active := ui.pal.accent
	inact := hexC(colNavTxt)
	// home (right, active pill)
	hp := ui.r.navHome
	cur := ui.page == pgHome
	pillCol := active
	if !cur {
		pillCol = hexC(colTrack)
	}
	ui.fillRound(c, walk.Rectangle{X: hp.X + px0(6), Y: hp.Y + px0(7), Width: hp.Width - px0(12), Height: hp.Height - px0(14)}, px0(22), pillCol)
	homeTxtCol := hexC(colWhite)
	if !cur {
		homeTxtCol = hexC(colSub)
	}
	cx, cy := hp.X+hp.Width/2, hp.Y+hp.Height/2-px0(6)
	if cur {
		ui.iconHome(c, cx, cy, px0(20), hexC(colWhite), pillCol)
	} else {
		ui.iconHome(c, cx, cy, px0(20), hexC(colNavTxt), hexC(colWhite))
	}
	ui.txtC(c, "خانه", walk.Rectangle{X: hp.X, Y: cy + px0(8), Width: hp.Width, Height: px0(18)}, ui.fNav, homeTxtCol)
	// servers (middle)
	sp := ui.r.navServers
	cur = ui.page == pgServers
	cx, cy = sp.X+sp.Width/2, sp.Y+sp.Height/2-px0(6)
	ui.iconGlobe(c, cx, cy, px0(9), mapCol(cur, active, inact))
	ui.txtC(c, "سرورها", walk.Rectangle{X: sp.X, Y: cy + px0(8), Width: sp.Width, Height: px0(18)}, ui.fNav, mapCol(cur, active, inact))
	// settings (left)
	tp := ui.r.navSettings
	cur = ui.page == pgSettings
	cx, cy = tp.X+tp.Width/2, tp.Y+tp.Height/2-px0(6)
	ui.iconGear(c, cx, cy, px0(9), mapCol(cur, active, inact), hexC(colWhite))
	ui.txtC(c, "تنظیمات", walk.Rectangle{X: tp.X, Y: cy + px0(8), Width: tp.Width, Height: px0(18)}, ui.fNav, mapCol(cur, active, inact))
}

func mapCol(active bool, a, b walk.Color) walk.Color {
	if active {
		return a
	}
	return b
}

func inflate(r walk.Rectangle, by int) walk.Rectangle {
	return walk.Rectangle{X: r.X - by, Y: r.Y - by, Width: r.Width + 2*by, Height: r.Height + 2*by}
}

// ---------- servers page ----------

func (ui *phoneUI) paintServers(c *walk.Canvas, w, h int, u float64) {
	px := func(v int) int { return int(float64(v) * u) }
	ui.iconBack(c, ui.r.back.X+ui.r.back.Width/2, ui.r.back.Y+ui.r.back.Height/2, px(16), hexC(colInk))
	ui.txtR(c, "سرورها", walk.Rectangle{X: ui.r.back.X - px(150), Y: ui.r.back.Y, Width: px(140), Height: ui.r.back.Height}, ui.fH2, hexC(colInk))

	listH := ui.r.scrollTrack.Height
	for i, rr := range ui.r.rows {
		idx := ui.rowIdx[i]
		sel := idx == ui.selIdx
		ui.fillRound(c, rr, px(14), hexC(colWhite))
		if sel {
			ui.strokeRound(c, rr, px(14), 2, ui.pal.accent)
			ui.iconCheck(c, rr.X+px(12), rr.Y+rr.Height/2-px(5), ui.pal.accent)
		}
		lab := ui.opts[idx].Label
		ui.txtR(c, lab, walk.Rectangle{X: rr.X + px(14), Y: rr.Y, Width: rr.Width - px(28), Height: rr.Height}, ui.fMed, hexC(colInk))
	}
	// scrollbar
	tr := ui.r.scrollTrack
	ui.fillRound(c, tr, px(2), blendC(hexC(colTrack), ui.pal.top, 0.4))
	if len(ui.opts) > 0 {
		pitch := px(60)
		content := len(ui.opts)*pitch + px(4)
		if content > listH {
			th := listH * listH / content
			if th < px(28) {
				th = px(28)
			}
			ty := tr.Y + (listH-th)*ui.scrollY/(content-listH)
			ui.fillRound(c, walk.Rectangle{X: tr.X, Y: ty, Width: tr.Width, Height: th}, px(2), hexC(colFaint))
		}
	}
	ui.paintNav(c, w, h, u)
}

// ---------- settings page ----------

func (ui *phoneUI) paintSettings(c *walk.Canvas, w, h int, u float64) {
	px := func(v int) int { return int(float64(v) * u) }
	m := px(18)
	ui.iconBack(c, ui.r.back.X+ui.r.back.Width/2, ui.r.back.Y+ui.r.back.Height/2, px(16), hexC(colInk))
	ui.txtR(c, "تنظیمات", walk.Rectangle{X: ui.r.back.X - px(150), Y: ui.r.back.Y, Width: px(140), Height: ui.r.back.Height}, ui.fH2, hexC(colInk))

	// proxy switch row
	ui.fillRound(c, ui.r.setProxy, px(14), hexC(colWhite))
	ui.txtR(c, "پروکسی خودکار ویندوز", walk.Rectangle{X: ui.r.setProxy.X + px(14), Y: ui.r.setProxy.Y, Width: ui.r.setProxy.Width - px(28), Height: ui.r.setProxy.Height}, ui.fMed, hexC(colInk))
	sw := walk.Rectangle{X: ui.r.setProxy.X + px(14), Y: ui.r.setProxy.Y + ui.r.setProxy.Height/2 - px(13), Width: px(46), Height: px(26)}
	if ui.snap.SysProxy {
		ui.fillRound(c, sw, px(13), ui.pal.accent)
		ui.fillEll(c, walk.Rectangle{X: sw.X + sw.Width - px(24), Y: sw.Y + px(2), Width: px(22), Height: px(22)}, hexC(colWhite))
	} else {
		ui.fillRound(c, sw, px(13), hexC(colTrack))
		ui.fillEll(c, walk.Rectangle{X: sw.X + px(2), Y: sw.Y + px(2), Width: px(22), Height: px(22)}, hexC(colWhite))
	}

	// account row
	ui.fillRound(c, ui.r.setAccount, px(14), hexC(colWhite))
	accTxt := "ورود به حساب فایرفاکس"
	accSub := "برای اتصال لازم است"
	if ui.snap.Email != "" {
		accTxt = ui.snap.Email
		accSub = "تغییر حساب / ورود دوباره"
	}
	ui.txtR(c, accTxt, walk.Rectangle{X: ui.r.setAccount.X + px(14), Y: ui.r.setAccount.Y + px(7), Width: ui.r.setAccount.Width - px(76), Height: px(22)}, ui.fMed, hexC(colInk))
	ui.txtR(c, accSub, walk.Rectangle{X: ui.r.setAccount.X + px(14), Y: ui.r.setAccount.Y + px(29), Width: ui.r.setAccount.Width - px(76), Height: px(18)}, ui.fTiny, ui.pal.accentDeep)
	ui.iconBack(c, ui.r.setAccount.X+px(30), ui.r.setAccount.Y+ui.r.setAccount.Height/2, px(14), hexC(colFaint))

	y := ui.r.setAccount.Y + px(62)
	if ui.snap.Email != "" {
		ui.fillRound(c, ui.r.setLogout, px(14), hexC(colWhite))
		ui.txtR(c, "خروج از حساب", walk.Rectangle{X: ui.r.setLogout.X + px(14), Y: ui.r.setLogout.Y, Width: ui.r.setLogout.Width - px(28), Height: ui.r.setLogout.Height}, ui.fMed, hexC(colRed))
		y = ui.r.setLogout.Y + px(62)
	}
	// exit app row
	ui.fillRound(c, ui.r.setExit, px(14), hexC(colWhite))
	ui.txtR(c, "خروج از برنامه", walk.Rectangle{X: ui.r.setExit.X + px(14), Y: ui.r.setExit.Y, Width: ui.r.setExit.Width - px(28), Height: ui.r.setExit.Height}, ui.fMed, hexC(colRed))

	// info card (ports)
	info := walk.Rectangle{X: m, Y: y + px(8), Width: w - 2*m, Height: px(48)}
	ui.fillRound(c, info, px(12), blendC(hexC(colWhite), ui.pal.top, 0.35))
	ui.txtC(c, fmt.Sprintf("SOCKS 127.0.0.1:%d   ·   HTTP 127.0.0.1:%d", ui.snap.SocksPort, ui.snap.HttpPort),
		walk.Rectangle{X: info.X, Y: info.Y + px(4), Width: info.Width, Height: px(20)}, ui.fTiny, hexC(colSub))
	ui.txtC(c, "FoxyVPN ویندوز — v"+appVersion,
		walk.Rectangle{X: info.X, Y: info.Y + px(24), Width: info.Width, Height: px(18)}, ui.fTiny, hexC(colFaint))

	// logs card
	logs := walk.Rectangle{X: m, Y: info.Y + px(56), Width: w - 2*m, Height: ui.r.navHome.Y - (info.Y + px(56)) - px(10)}
	if logs.Height > px(60) {
		ui.fillRound(c, logs, px(12), hexC(colWhite))
		ui.txtR(c, "گزارش اخیر", walk.Rectangle{X: logs.X + px(12), Y: logs.Y + px(6), Width: logs.Width - px(24), Height: px(18)}, ui.fTiny, hexC(colSub))
		n := (logs.Height - px(30)) / px(16)
		if n > 5 {
			n = 5
		}
		if n > len(ui.logTail) {
			n = len(ui.logTail)
		}
		for i := 0; i < n; i++ {
			line := ui.logTail[len(ui.logTail)-n+i]
			ui.txtL(c, line, walk.Rectangle{X: logs.X + px(12), Y: logs.Y + px(26) + i*px(16), Width: logs.Width - px(24), Height: px(15)}, ui.fTiny, hexC(colSub))
		}
	}
	ui.paintNav(c, w, h, u)
}

// ---------- login page ----------

func (ui *phoneUI) paintLogin(c *walk.Canvas, w, h int, u float64) {
	px := func(v int) int { return int(float64(v) * u) }
	m := px(18)
	ui.iconBack(c, ui.r.backLogin.X+px(14), ui.r.backLogin.Y+ui.r.backLogin.Height/2, px(15), hexC(colInk))
	ui.txtR(c, "بازگشت", walk.Rectangle{X: ui.r.backLogin.X + px(28), Y: ui.r.backLogin.Y, Width: px(60), Height: ui.r.backLogin.Height}, ui.fSmall, hexC(colInk))

	ui.txtC(c, "ورود با حساب فایرفاکس", walk.Rectangle{X: m, Y: px(62), Width: w - 2*m, Height: px(34)}, ui.fH2, hexC(colInk))
	ui.txtCR(c, "برای ساخت تونل رایگان از سهمیهٔ گاردین", walk.Rectangle{X: m, Y: px(96), Width: w - 2*m, Height: px(20)}, ui.fSmall, hexC(colSub))

	if ui.loginErr != "" {
		ui.txtWrap(c, ui.loginErr, walk.Rectangle{X: m + px(4), Y: px(276), Width: w - 2*m - px(8), Height: px(38)}, ui.fSmall, hexC(colRed))
	}

	btn := ui.r.btnLogin
	btnCol := ui.pal.accent
	if ui.loginBusy != 0 {
		btnCol = blendC(ui.pal.accent, hexC(colWhite), 0.45)
	}
	ui.fillRound(c, btn, px(23), btnCol)
	btnTxt := "ورود"
	if ui.loginBusy != 0 {
		btnTxt = "در حال ورود…"
	}
	ui.txtC(c, btnTxt, btn, ui.fName, hexC(colWhite))

	ui.txtCR(c, "با ورود، همان حساب فایرفاکس و سهمیهٔ رایگان آن استفاده می‌شود",
		walk.Rectangle{X: m, Y: px(382), Width: w - 2*m, Height: px(20)}, ui.fTiny, hexC(colFaint))
}

// ---------- quota / elapsed helpers ----------

func quotaRatio(s Snapshot) float64 {
	if s.QuotaMax == nil || s.QuotaRemain == nil || *s.QuotaMax <= 0 {
		return -1
	}
	used := *s.QuotaMax - *s.QuotaRemain
	r := float64(used) / float64(*s.QuotaMax)
	if r < 0 {
		r = 0
	}
	if r > 1 {
		r = 1
	}
	return r
}

func elapsedText(s Snapshot) string {
	if s.State != StateConnected || s.Since == "" {
		return "00:00:00"
	}
	t0, err := time.Parse(time.RFC3339, s.Since)
	if err != nil {
		return "00:00:00"
	}
	d := int(time.Since(t0).Seconds())
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("%02d:%02d:%02d", d/3600, (d/60)%60, d%60)
}

// ---------- mouse handling ----------

func (ui *phoneUI) onDown(x, y int, btn walk.MouseButton) {
	if btn != walk.LeftButton {
		return
	}
	in := func(r walk.Rectangle) bool {
		return x >= r.X && x < r.X+r.Width && y >= r.Y && y < r.Y+r.Height
	}
	switch ui.page {
	case pgHome:
		switch {
		case in(inflate(ui.r.power, pxHit(ui, 14))):
			ui.onPower()
		case in(ui.r.pill):
			go ui.core.SetSysProxyEnabled(!ui.snap.SysProxy)
		case in(ui.r.navServers):
			ui.setPage(pgServers)
		case in(ui.r.navSettings):
			ui.setPage(pgSettings)
		case in(ui.r.navHome):
			ui.setPage(pgHome)
		}
	case pgServers:
		switch {
		case in(ui.r.back):
			ui.setPage(pgHome)
		case in(ui.r.scrollTrack):
			ui.drag = true
			ui.dragY = y
		case in(ui.r.navHome):
			ui.setPage(pgHome)
		case in(ui.r.navSettings):
			ui.setPage(pgSettings)
		default:
			for i, rr := range ui.r.rows {
				if in(rr) {
					idx := ui.rowIdx[i]
					ui.selIdx = idx
					o := ui.opts[idx]
					go ui.core.SetServerChoice(o.Country, o.City)
					break
				}
			}
		}
	case pgSettings:
		switch {
		case in(ui.r.back):
			ui.setPage(pgHome)
		case in(ui.r.setProxy):
			go ui.core.SetSysProxyEnabled(!ui.snap.SysProxy)
		case in(ui.r.setAccount):
			ui.setPage(pgLogin)
		case ui.snap.Email != "" && in(ui.r.setLogout):
			go func() { _ = ui.core.Logout() }()
		case in(ui.r.setExit):
			ui.exitApp()
		case in(ui.r.navHome):
			ui.setPage(pgHome)
		case in(ui.r.navServers):
			ui.setPage(pgServers)
		}
	case pgLogin:
		switch {
		case in(ui.r.backLogin):
			ui.setPage(pgHome)
		case in(ui.r.btnLogin):
			ui.onLoginClick()
		}
	}
	ui.canvas.Invalidate()
}

func pxHit(ui *phoneUI, v int) int {
	b := ui.canvas.Bounds()
	if b.Width <= 0 {
		return v
	}
	return int(float64(v) * float64(b.Width) / 375.0)
}

func (ui *phoneUI) onMove(x, y int, btn walk.MouseButton) {
	if ui.drag && ui.page == pgServers {
		ui.scrollY -= (y - ui.dragY)
		ui.dragY = y
		ui.canvas.Invalidate()
	}
}

func (ui *phoneUI) onUp(x, y int, btn walk.MouseButton) {
	ui.drag = false
}
