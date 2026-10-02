//go:build windows

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	className = "CountryIPFilterWindow"

	idTitle      = 101
	idDesc       = 102
	idProgress   = 103
	idMain       = 104
	idOff        = 105
	idRefresh    = 106
	idDetails    = 107
	idCopy       = 108
	idPortsHead  = 109
	idPortList   = 110
	idAddLabel   = 111
	idPortCombo  = 112
	idAdd        = 113
	idRemovePort = 114
	idProbHead   = 115
	idNoProb     = 116
	idInfo       = 117
	idLog        = 118
	idLang       = 119
	idCountHead  = 120
	idCountList  = 121
	idCountCombo = 122
	idAddCountry = 123
	idRemCountry = 124
	idProtoCombo = 125
	idAddApp     = 126
	idSlotText   = 200 // + i
	idSlotButton = 300 // + i

	wmRun = WM_APP + 1

	levelBusy Level = 100
)

var secondIDs = []int{idOff, idRefresh, idDetails, idCopy}

type palette struct{ bg, fg uint32 }

var palettes = map[Level]palette{
	LevelGrey:   {rgb(240, 242, 245), rgb(52, 58, 68)},
	LevelGreen:  {rgb(225, 245, 232), rgb(20, 98, 50)},
	LevelOrange: {rgb(255, 242, 218), rgb(128, 70, 0)},
	LevelRed:    {rgb(253, 231, 231), rgb(160, 28, 28)},
	levelBusy:   {rgb(232, 240, 254), rgb(24, 80, 170)},
}

// colour of the "state" column and of the bar beside each problem
var stateColors = map[Level]uint32{
	LevelGrey:   rgb(90, 96, 106),
	LevelGreen:  rgb(21, 128, 61),
	LevelOrange: rgb(194, 110, 0),
	LevelRed:    rgb(200, 30, 30),
}

// countryOrder: the codes in the order of the country list (sorted by name
// in the window's language).
func countryOrder() []string {
	var out []string
	for _, c := range countries {
		out = append(out, c.Code)
	}
	sort.SliceStable(out, func(i, j int) bool { return lessName(CountryName(out[i]), CountryName(out[j])) })
	return out
}

type gui struct {
	hwnd, hinst                  uintptr
	font, bold, big, head, small uintptr
	dpi                          int
	ctl                          map[int]uintptr
	brushes                      map[Level]uintptr
	white, sepBrush              uintptr
	barBrush                     map[bool]uintptr
	style, exStyle               uintptr

	app *App

	mu    sync.Mutex
	queue []func()

	// touched only on the UI thread
	busy     bool
	stepText string
	view     View
	haveView bool
	details  bool
	rows     []PortRow // rows now in the list
	selKey   string    // the port or program the user selected (kept across refreshes)
	filling  bool
	ccOrder  []string // codes of the country box, in its order
	ccShown  []string // codes now in the list of chosen countries
	selCC    string   // the chosen country the user selected
	backAt   uintptr  // tick count when the details view was closed
	lay      Layout
	banner   Level
}

var theGUI *gui

func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	if g := theGUI; g != nil && g.hwnd != 0 {
		if r, ok := g.handle(uint32(msg), wparam, lparam); ok {
			return r
		}
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func (g *gui) s(v int) int32 { return int32(v * g.dpi / 96) }

func (g *gui) makeFont(tenths, weight int) uintptr {
	h := -(tenths*g.dpi + 360) / 720
	f, _, _ := pCreateFontW.Call(uintptr(int32(h)), 0, 0, 0, uintptr(weight), 0, 0, 0,
		1 /*DEFAULT_CHARSET*/, 0, 0, 5 /*CLEARTYPE_QUALITY*/, 0, uintptr(unsafe.Pointer(u16("Segoe UI"))))
	return f
}

func (g *gui) create() error {
	pSetProcessDPIAware.Call()
	icc := INITCOMMONCONTROLSEX{ICC: 0x1 | 0x20 | 0x4000} // list view, progress, standard
	icc.Size = uint32(unsafe.Sizeof(icc))
	pInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
	g.hinst, _, _ = pGetModuleHandleW.Call(0)
	dc, _, _ := pGetDC.Call(0)
	d, _, _ := pGetDeviceCaps.Call(dc, LOGPIXELSX)
	pReleaseDC.Call(0, dc)
	g.dpi = int(d)
	if g.dpi < 96 {
		g.dpi = 96
	}
	g.font = g.makeFont(90, 400)
	g.small = g.makeFont(85, 400)
	g.head = g.makeFont(100, 700)
	g.big = g.makeFont(140, 700)
	g.bold = g.makeFont(95, 700)
	g.ctl = map[int]uintptr{}
	g.brushes = map[Level]uintptr{}
	for l, p := range palettes {
		g.brushes[l] = solidBrush(p.bg)
	}
	g.white = solidBrush(rgb(255, 255, 255))
	g.sepBrush = solidBrush(rgb(226, 229, 234))
	g.barBrush = map[bool]uintptr{true: solidBrush(stateColors[LevelRed]), false: solidBrush(stateColors[LevelOrange])}

	icon, _, _ := pLoadIconW.Call(g.hinst, 1)
	cursor, _, _ := pLoadCursorW.Call(0, IDC_ARROW)
	wc := WNDCLASSEXW{
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     g.hinst,
		HIcon:         icon,
		HIconSm:       icon,
		HCursor:       cursor,
		HbrBackground: g.white,
		LpszClassName: u16(className),
	}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassEx: %v", err)
	}

	g.style = uintptr(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN)
	g.exStyle = uintptr(WS_EX_CONTROLPARENT)
	if lang == "fa" {
		g.exStyle |= WS_EX_LAYOUTRTL // Persian: the whole window is mirrored (right to left)
	}
	w, h := g.windowSize(firstClientH)
	work := g.workArea()
	x := work.Left + (work.Right-work.Left-w)/2
	y := work.Top + (work.Bottom-work.Top-h)/3
	if x < work.Left {
		x = work.Left
	}
	if y < work.Top {
		y = work.Top
	}
	hwnd, _, err := pCreateWindowExW.Call(g.exStyle, uintptr(unsafe.Pointer(u16(className))), uintptr(unsafe.Pointer(u16(appTitle()))),
		g.style, uintptr(x), uintptr(y), uintptr(w), uintptr(h), 0, 0, g.hinst, 0)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowEx: %v", err)
	}
	g.hwnd = hwnd

	// ---- controls (positions come from computeLayout)
	g.add(idTitle, "STATIC", T("در حال بررسی…"), SS_NOPREFIX, 0, g.big)
	g.add(idDesc, "STATIC", T("برنامه در حال خواندن تنظیمات Windows Firewall است."), SS_NOPREFIX, 0, g.font)
	g.add(idProgress, "msctls_progress32", "", PBS_MARQUEE, 0, 0)
	sendMessage(g.ctl[idProgress], PBM_SETMARQUEE, 1, 30)

	g.add(idMain, "BUTTON", "", WS_TABSTOP|BS_DEFPUSHBUTTON, 0, g.bold)
	g.add(idOff, "BUTTON", rtlText(T(MainOff)), WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)
	g.add(idRefresh, "BUTTON", rtlText(T(MainCheck)), WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)
	g.add(idDetails, "BUTTON", T("جزئیات فنی"), WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)
	g.add(idCopy, "BUTTON", T("کپی متن"), WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)

	g.add(idCountHead, "STATIC", T("کشورها (فقط این کشورها می‌توانند وصل شوند)"), SS_NOPREFIX, 0, g.head)
	g.add(idCountList, "LISTBOX", "", WS_TABSTOP|WS_VSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT, WS_EX_CLIENTEDGE, g.font)
	g.add(idCountCombo, "COMBOBOX", "", WS_TABSTOP|WS_VSCROLL|CBS_DROPDOWNLIST, 0, g.font)
	cc := g.ctl[idCountCombo]
	g.ccOrder = countryOrder()
	home := regionCountry()
	pick := -1
	for i, code := range g.ccOrder {
		sendMessage(cc, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(u16(countryLabelPlain(code)))))
		if code == home {
			pick = i
		}
	}
	sendMessage(cc, CB_SETMINVISIBLE, 16, 0)
	sendMessage(cc, CB_SETDROPPEDWIDTH, uintptr(g.s(260)), 0)
	if pick >= 0 {
		sendMessage(cc, CB_SETCURSEL, uintptr(pick), 0)
	}
	g.add(idAddCountry, "BUTTON", T("افزودن کشور"), WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)
	g.add(idRemCountry, "BUTTON", T("حذف کشور انتخاب‌شده"), WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)

	g.add(idPortsHead, "STATIC", T("پورت‌ها و برنامه‌ها"), SS_NOPREFIX, 0, g.head)
	g.add(idPortList, "SysListView32", "", WS_TABSTOP|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS|LVS_NOSORTHEADER, WS_EX_CLIENTEDGE, g.font)
	lv := g.ctl[idPortList]
	sendMessage(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER)
	if pSetWindowTheme.Find() == nil {
		pSetWindowTheme.Call(lv, uintptr(unsafe.Pointer(u16("Explorer"))), 0) // light selection colour
	}
	for i, c := range []struct {
		title string
		w     int
	}{{T("مورد"), 72}, {T("سرویس"), 116}, {T("وضعیت"), 238}} {
		col := LVCOLUMNW{Mask: LVCF_TEXT | LVCF_WIDTH, Cx: g.s(c.w), PszText: u16(c.title)}
		sendMessage(lv, LVM_INSERTCOLUMNW, uintptr(i), uintptr(unsafe.Pointer(&col)))
	}
	g.add(idAddLabel, "STATIC", T("افزودن پورت:"), SS_NOPREFIX, 0, g.font)
	g.add(idProtoCombo, "COMBOBOX", "", WS_TABSTOP|CBS_DROPDOWNLIST, 0, g.font)
	for _, p := range []string{"TCP", "UDP"} {
		sendMessage(g.ctl[idProtoCombo], CB_ADDSTRING, 0, uintptr(unsafe.Pointer(u16(p))))
	}
	sendMessage(g.ctl[idProtoCombo], CB_SETCURSEL, 0, 0)
	g.add(idPortCombo, "COMBOBOX", "", WS_TABSTOP|WS_VSCROLL|CBS_DROPDOWN|CBS_AUTOHSCROLL, 0, g.font)
	cb := g.ctl[idPortCombo]
	for _, k := range wellKnown {
		sendMessage(cb, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(u16(knownLabel(k)))))
	}
	sendMessage(cb, CB_SETMINVISIBLE, 16, 0)
	sendMessage(cb, CB_SETDROPPEDWIDTH, uintptr(g.s(250)), 0)
	cue := u16(T("مثلاً 808"))
	sendMessage(cb, CB_SETCUEBANNER, 0, uintptr(unsafe.Pointer(cue)))
	g.add(idAdd, "BUTTON", T("افزودن پورت"), WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)
	g.add(idAddApp, "BUTTON", T("افزودن برنامه (exe)…"), WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)
	g.add(idRemovePort, "BUTTON", T("حذف مورد انتخاب‌شده"), WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)

	g.add(idProbHead, "STATIC", T("مشکل‌ها"), SS_NOPREFIX, 0, g.head)
	g.add(idNoProb, "STATIC", T("✔  مشکلی نیست."), SS_NOPREFIX, 0, g.font)
	for i := 0; i < maxRows; i++ {
		g.add(idSlotText+i, "STATIC", "", SS_NOPREFIX, 0, g.font)
		g.add(idSlotButton+i, "BUTTON", "", WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)
	}
	g.add(idInfo, "STATIC", "", SS_NOPREFIX, 0, g.small)
	langName := "English"
	if lang == "en" {
		langName = "فارسی"
	}
	g.add(idLang, "BUTTON", langName, WS_TABSTOP|BS_PUSHBUTTON, 0, g.font)
	g.add(idLog, "EDIT", "", WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY, WS_EX_CLIENTEDGE, g.font)
	sendMessage(g.ctl[idLog], EM_SETLIMITTEXT, 4<<20, 0)

	g.banner = LevelGrey
	g.render()
	pShowWindow.Call(hwnd, SW_SHOW)
	pUpdateWindow.Call(hwnd)
	pSetForegroundWindow.Call(hwnd)
	return nil
}

func (g *gui) windowSize(ch int) (int32, int32) {
	rc := RECT{0, 0, g.s(layoutW), g.s(ch)}
	pAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&rc)), g.style, 0, g.exStyle)
	return rc.Right - rc.Left, rc.Bottom - rc.Top
}

func (g *gui) workArea() RECT {
	var rc RECT
	if r, _, _ := pSystemParametersInfoW.Call(SPI_GETWORKAREA, 0, uintptr(unsafe.Pointer(&rc)), 0); r == 0 {
		sw, _, _ := pGetSystemMetrics.Call(SM_CXSCREEN)
		sh, _, _ := pGetSystemMetrics.Call(SM_CYSCREEN)
		rc = RECT{0, 0, int32(sw), int32(sh)}
	}
	return rc
}

// maxClientH: the tallest client area (96-DPI units) that fits on the screen.
func (g *gui) maxClientH() int {
	work := g.workArea()
	_, frame := g.windowSize(0)
	px := int(work.Bottom-work.Top) - int(frame)
	return px * 96 / g.dpi
}

func (g *gui) add(id int, class, text string, style, exStyle uint32, font uintptr) {
	hw, _, _ := pCreateWindowExW.Call(uintptr(exStyle), uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(text))),
		uintptr(WS_CHILD|style), 0, 0, 10, 10, g.hwnd, uintptr(id), g.hinst, 0)
	if font != 0 {
		sendMessage(hw, WM_SETFONT, font, 1)
	}
	g.ctl[id] = hw
}

// measure: height of text wrapped at width, both in 96-DPI units.
func (g *gui) measure(text string, width int) int {
	dc, _, _ := pGetDC.Call(g.hwnd)
	old, _, _ := pSelectObject.Call(dc, g.font)
	rc := RECT{0, 0, g.s(width), 0}
	p := u16(text)
	pDrawTextW.Call(dc, uintptr(unsafe.Pointer(p)), ^uintptr(0), uintptr(unsafe.Pointer(&rc)), DT_CALCRECT|DT_WORDBREAK|DT_NOPREFIX|rtlDrawFlag())
	pSelectObject.Call(dc, old)
	pReleaseDC.Call(g.hwnd, dc)
	return (int(rc.Bottom-rc.Top)*96 + g.dpi - 1) / g.dpi
}

func (g *gui) place(id int, b Box) {
	h := g.ctl[id]
	if !b.Visible() {
		show(h, false)
		return
	}
	pMoveWindow.Call(h, uintptr(g.s(b.X)), uintptr(g.s(b.Y)), uintptr(g.s(b.W)), uintptr(g.s(b.H)), 1)
	show(h, true)
}

// ---------------------------------------------------------------- drawing the state

func (g *gui) render() {
	v := g.view
	level, title, desc := v.Level, v.Title, v.Desc
	switch {
	case g.busy:
		level, title, desc = levelBusy, T("لطفاً صبر کنید…"), g.stepText
		if desc == "" {
			desc = T("در حال انجام کار…")
		}
	case !g.haveView:
		level, title, desc = levelBusy, T("در حال بررسی…"), T("برنامه در حال خواندن تنظیمات Windows Firewall است.")
	}
	g.banner = level
	setRTL(g.ctl[idTitle], title)
	setRTL(g.ctl[idDesc], desc)

	L := computeLayout(v, g.haveView, g.details, g.busy || !g.haveView, g.measure, g.maxClientH())
	g.lay = L
	g.resize(L.ClientH)

	g.place(idTitle, L.Title)
	g.place(idDesc, L.Desc)
	g.place(idProgress, L.Progress)
	g.place(idMain, L.Main)
	for i, id := range secondIDs {
		g.place(id, L.Second[i])
	}
	g.place(idCountHead, L.CountriesHead)
	g.place(idCountList, L.CountryList)
	g.place(idCountCombo, L.CountryCombo)
	g.place(idAddCountry, L.AddCountry)
	g.place(idRemCountry, L.RemoveCountry)
	g.place(idPortsHead, L.PortsHead)
	g.place(idPortList, L.PortList)
	g.place(idAddLabel, L.AddLabel)
	g.place(idProtoCombo, L.ProtoCombo)
	g.place(idPortCombo, L.PortCombo)
	g.place(idAdd, L.AddButton)
	g.place(idAddApp, L.AddApp)
	g.place(idRemovePort, L.RemoveButton)
	g.place(idProbHead, L.ProbHead)
	g.place(idNoProb, L.NoProb)
	g.place(idInfo, L.Info)
	g.place(idLang, L.Lang)
	g.place(idLog, L.Log)
	for i := 0; i < maxRows; i++ {
		var r ProblemRow
		if i < len(L.Rows) {
			r = L.Rows[i]
			p := v.Problems[i]
			setRTL(g.ctl[idSlotText+i], p.Text)
			setRTL(g.ctl[idSlotButton+i], p.Button)
		}
		g.place(idSlotText+i, r.Text)
		g.place(idSlotButton+i, r.Button)
	}

	if g.haveView {
		setRTL(g.ctl[idMain], T(v.Main))
		if g.details {
			setRTL(g.ctl[idDetails], T("بازگشت"))
		} else {
			setRTL(g.ctl[idDetails], T("جزئیات فنی"))
		}
		head := T("مشکل‌ها")
		if n := len(v.Problems); n > 0 {
			head = T("مشکل‌ها (%d)", n)
			if L.Hidden > 0 {
				head = T("مشکل‌ها (%d) — %d مورد دیگر جا نشد؛ همه در «جزئیات فنی» هست", n, L.Hidden)
			}
		}
		setRTL(g.ctl[idProbHead], head)
		setRTL(g.ctl[idInfo], v.Info)
		g.fillPorts()
		g.fillCountries()
	}
	g.enableAll()
	pInvalidateRect.Call(g.hwnd, 0, 1)
}

// resize keeps the window as tall as its content, inside the screen.
func (g *gui) resize(clientH int) {
	w, h := g.windowSize(clientH)
	var cur RECT
	pGetWindowRect.Call(g.hwnd, uintptr(unsafe.Pointer(&cur)))
	if cur.Bottom-cur.Top == h && cur.Right-cur.Left == w {
		return
	}
	work := g.workArea()
	y := cur.Top
	if y+h > work.Bottom {
		y = work.Bottom - h
	}
	if y < work.Top {
		y = work.Top
	}
	pSetWindowPos.Call(g.hwnd, 0, uintptr(cur.Left), uintptr(y), uintptr(w), uintptr(h), SWP_NOZORDER|SWP_NOACTIVATE)
}

func (g *gui) fillPorts() {
	lv := g.ctl[idPortList]
	keep := g.selKey
	g.filling = true
	defer func() { g.filling = false }()
	sendMessage(lv, LVM_DELETEALLITEMS, 0, 0)
	g.rows = append([]PortRow(nil), g.view.Rows...)
	found := false
	for i, r := range g.view.Rows {
		it := LVITEMW{Mask: LVIF_TEXT | LVIF_PARAM, IItem: int32(i), PszText: u16(r.Item), LParam: uintptr(r.Level)}
		sendMessage(lv, LVM_INSERTITEMW, 0, uintptr(unsafe.Pointer(&it)))
		for sub, t := range []string{r.Service, rtlText(T(r.State))} {
			st := LVITEMW{ISubItem: int32(sub + 1), PszText: u16(t)}
			sendMessage(lv, LVM_SETITEMTEXTW, uintptr(i), uintptr(unsafe.Pointer(&st)))
		}
		if r.Key == keep {
			st := LVITEMW{State: LVIS_SELECTED | LVIS_FOCUSED, StateMask: LVIS_SELECTED | LVIS_FOCUSED}
			sendMessage(lv, LVM_SETITEMSTATE, uintptr(i), uintptr(unsafe.Pointer(&st)))
			sendMessage(lv, LVM_ENSUREVISIBLE, uintptr(i), 0)
			found = true
		}
	}
	if !found {
		g.selKey = "" // the selected entry is gone: nothing is selected
	}
}

// fillCountries shows the chosen countries, keeping the selection.
func (g *gui) fillCountries() {
	lb := g.ctl[idCountList]
	sendMessage(lb, LB_RESETCONTENT, 0, 0)
	g.ccShown = append([]string(nil), g.view.Countries...)
	found := false
	for i, code := range g.ccShown {
		sendMessage(lb, LB_ADDSTRING, 0, uintptr(unsafe.Pointer(u16(countryLabelPlain(code)))))
		if code == g.selCC {
			sendMessage(lb, LB_SETCURSEL, uintptr(i), 0)
			found = true
		}
	}
	if !found {
		g.selCC = ""
	}
}

// readSelection: which row is selected in the list, as shown.
func (g *gui) readSelection() {
	if g.filling {
		return
	}
	i := int(int32(sendMessage(g.ctl[idPortList], LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED)))
	g.selKey = ""
	if i >= 0 && i < len(g.rows) {
		g.selKey = g.rows[i].Key
	}
}

func (g *gui) enableAll() {
	on := !g.busy && g.haveView
	for _, id := range []int{idOff, idRefresh, idDetails, idCopy, idPortList, idCountList, idLang} {
		enable(g.ctl[id], on)
	}
	// ports and countries can be changed only when the firewall could be read
	edit := on && !g.view.Unknown
	for _, id := range []int{idPortCombo, idProtoCombo, idAdd, idAddApp, idCountCombo, idAddCountry} {
		enable(g.ctl[id], edit)
	}
	enable(g.ctl[idMain], on && g.view.Action != ActDisabled)
	enable(g.ctl[idRemovePort], edit && g.selKey != "")
	enable(g.ctl[idRemCountry], edit && g.selCC != "")
	for i := 0; i < maxRows; i++ {
		enable(g.ctl[idSlotButton+i], on)
	}
}

// ---------------------------------------------------------------- thread plumbing

// do runs f on the UI thread.
func (g *gui) do(f func()) {
	g.mu.Lock()
	g.queue = append(g.queue, f)
	g.mu.Unlock()
	postMessage(g.hwnd, wmRun, 0, 0)
}

func (g *gui) drain() {
	g.mu.Lock()
	q := g.queue
	g.queue = nil
	g.mu.Unlock()
	for _, f := range q {
		f()
	}
}

// work runs job in the background with the buttons disabled.
func (g *gui) work(job func()) {
	if g.busy {
		return
	}
	g.busy = true
	g.stepText = ""
	g.render()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				g.app.log(T("خطای پیش‌بینی‌نشده: %v"), r)
				g.Tell(T("یک خطای پیش‌بینی‌نشده رخ داد و کار نیمه‌تمام ماند. «%s» را بزنید؛ اگر تکرار شد، %s", T(MainCheck), T(support)), LevelRed)
			}
			g.do(func() {
				pShutdownBlockReasonDestroy.Call(g.hwnd)
				g.busy = false
				g.render()
				// the main button is the safe place for the keyboard focus
				focus := g.ctl[idMain]
				if g.details || !isVisible(focus) || !isEnabled(focus) {
					focus = g.ctl[idDetails]
				}
				pSetFocus.Call(focus)
			})
		}()
		job()
	}()
}

func isEnabled(h uintptr) bool {
	r, _, _ := pIsWindowEnabled.Call(h)
	return r != 0
}

func isVisible(h uintptr) bool {
	r, _, _ := pIsWindowVisible.Call(h)
	return r != 0
}

func (g *gui) toggleDetails() {
	g.details = !g.details
	if g.details {
		// the earlier lines stay: they may hold the error the user wants to copy
		g.work(g.app.Details)
		return
	}
	g.backAt, _, _ = pGetTickCount.Call()
	g.render()
}

// ---------------------------------------------------------------- UI interface (called from the worker)

func (g *gui) Log(line string) {
	g.do(func() {
		h := g.ctl[idLog]
		n, _, _ := pGetWindowTextLengthW.Call(h)
		if n > 3<<20 { // near the 4M limit: drop the oldest part
			sendMessage(h, EM_SETSEL, 0, 1<<20)
			empty := u16("")
			sendMessage(h, EM_REPLACESEL, 0, uintptr(unsafe.Pointer(empty)))
			n, _, _ = pGetWindowTextLengthW.Call(h)
		}
		sendMessage(h, EM_SETSEL, n, n)
		p := u16(rtlText(line) + "\r\n")
		sendMessage(h, EM_REPLACESEL, 0, uintptr(unsafe.Pointer(p)))
		sendMessage(h, EM_SCROLLCARET, 0, 0)
	})
}

func (g *gui) Progress(step string) {
	g.do(func() {
		g.stepText = step
		if g.busy {
			setRTL(g.ctl[idDesc], step)
		}
	})
}

func (g *gui) Ask(text string, warning bool) bool {
	ch := make(chan bool, 1)
	g.do(func() {
		flags := uintptr(MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION)
		if warning {
			flags = MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING
		}
		ch <- messageBox(g.hwnd, text, appTitle(), flags) == IDYES
	})
	return <-ch
}

func (g *gui) Tell(text string, level Level) {
	ch := make(chan struct{})
	g.do(func() {
		flags := uintptr(MB_OK | MB_ICONINFO)
		switch level {
		case LevelRed:
			flags = MB_OK | MB_ICONERROR
		case LevelOrange:
			flags = MB_OK | MB_ICONWARNING
		}
		messageBox(g.hwnd, text, appTitle(), flags)
		close(ch)
	})
	<-ch
}

func (g *gui) Show(v View) {
	g.do(func() {
		g.view, g.haveView = v, true
		g.render()
	})
}

func (g *gui) OpenURL(url string) bool {
	ch := make(chan bool, 1)
	g.do(func() {
		// through Explorer, so the browser does not run as Administrator
		r, _, _ := pShellExecuteW.Call(g.hwnd, uintptr(unsafe.Pointer(u16("open"))), uintptr(unsafe.Pointer(u16(system32dir("explorer.exe")))),
			uintptr(unsafe.Pointer(u16(`"`+url+`"`))), 0, 1)
		ch <- r > 32
	})
	return <-ch
}

func (g *gui) PickFile(program bool) string {
	ch := make(chan string, 1)
	g.do(func() { ch <- g.pickFile(program) })
	return <-ch
}

// pickFile shows the standard "open file" window (UI thread only).
func (g *gui) pickFile(program bool) string {
	buf := make([]uint16, 1024)
	filter := utf16z(T("لیست IP")+" (json, txt, html)", "*.json;*.txt;*.htm;*.html", T("همه‌ی فایل‌ها"), "*.*")
	title := u16(T("انتخاب فایل لیست IP"))
	if program {
		filter = utf16z(T("برنامه")+" (exe)", "*.exe")
		title = u16(T("انتخاب فایل برنامه"))
	}
	ofn := OPENFILENAMEW{
		Owner:   g.hwnd,
		Filter:  &filter[0],
		File:    &buf[0],
		MaxFile: uint32(len(buf)),
		Title:   title,
		Flags:   OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR,
	}
	ofn.StructSize = uint32(unsafe.Sizeof(ofn))
	r, _, _ := pGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// copyText puts text on the clipboard.
func (g *gui) copyText(s string) bool {
	u, err := syscall.UTF16FromString(strings.NewReplacer("\u202A", "", "\u202C", "", "\u200F", "").Replace(s))
	if err != nil {
		return false
	}
	if r, _, _ := pOpenClipboard.Call(g.hwnd); r == 0 {
		return false
	}
	defer pCloseClipboard.Call()
	pEmptyClipboard.Call()
	size := uintptr(len(u) * 2)
	hmem, _, _ := pGlobalAlloc.Call(GMEM_MOVEABLE, size)
	if hmem == 0 {
		return false
	}
	p, _, _ := pGlobalLock.Call(hmem)
	if p == 0 {
		pGlobalFree.Call(hmem)
		return false
	}
	copy(unsafe.Slice((*uint16)(asPtr(p)), len(u)), u)
	pGlobalUnlock.Call(hmem)
	if r, _, _ := pSetClipboardData.Call(CF_UNICODETEXT, hmem); r == 0 {
		pGlobalFree.Call(hmem)
		return false
	}
	return true
}

// ---------------------------------------------------------------- messages

func (g *gui) handle(msg uint32, wparam, lparam uintptr) (uintptr, bool) {
	switch msg {
	case wmRun:
		g.drain()
		return 0, true
	case WM_ERASEBKGND:
		hdc := wparam
		var rc RECT
		pGetClientRect.Call(g.hwnd, uintptr(unsafe.Pointer(&rc)))
		pFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), g.white)
		b := g.lay.Banner
		br := RECT{g.s(b.X), g.s(b.Y), g.s(b.X + b.W), g.s(b.Y + b.H)}
		pFillRect.Call(hdc, uintptr(unsafe.Pointer(&br)), g.brushes[g.banner])
		for _, y := range g.lay.Sep {
			sr := RECT{g.s(16), g.s(y), g.s(layoutW - 16), g.s(y) + 1}
			pFillRect.Call(hdc, uintptr(unsafe.Pointer(&sr)), g.sepBrush)
		}
		for i, r := range g.lay.Rows {
			if i < len(g.view.Problems) {
				bar := RECT{g.s(r.Bar.X), g.s(r.Bar.Y), g.s(r.Bar.X + r.Bar.W), g.s(r.Bar.Y + r.Bar.H)}
				pFillRect.Call(hdc, uintptr(unsafe.Pointer(&bar)), g.barBrush[g.view.Problems[i].Severe])
			}
		}
		return 1, true
	case WM_CTLCOLORSTATIC:
		hdc, ctrl := wparam, lparam
		switch ctrl {
		case g.ctl[idTitle], g.ctl[idDesc]:
			p := palettes[g.banner]
			pSetTextColor.Call(hdc, uintptr(p.fg))
			pSetBkColor.Call(hdc, uintptr(p.bg))
			return g.brushes[g.banner], true
		case g.ctl[idNoProb]:
			return g.colorText(hdc, stateColors[LevelGreen]), true
		case g.ctl[idInfo]:
			return g.colorText(hdc, rgb(100, 106, 116)), true
		}
		return g.colorText(hdc, rgb(33, 37, 41)), true
	case WM_CTLCOLORBTN:
		return g.white, true
	case WM_NOTIFY:
		return g.notify(asPtr(lparam))
	case WM_COMMAND:
		id := int(wparam & 0xFFFF)
		code := int((wparam >> 16) & 0xFFFF)
		g.command(id, code)
		return 0, true
	case WM_QUERYENDSESSION:
		// logoff or shutdown in the middle of changing rules: ask Windows to wait
		if g.busy {
			pShutdownBlockReasonCreate.Call(g.hwnd, uintptr(unsafe.Pointer(u16("Country IP Filter is changing Windows Firewall rules"))))
			return 0, true
		}
		return 1, true
	case WM_CLOSE:
		if g.busy {
			messageBox(g.hwnd, T("کار در حال انجام است. لطفاً صبر کنید تا تمام شود."), appTitle(), MB_OK|MB_ICONINFO)
			return 0, true
		}
		pDestroyWindow.Call(g.hwnd)
		return 0, true
	case WM_DESTROY:
		pPostQuitMessage.Call(0)
		return 0, true
	}
	return 0, false
}

func (g *gui) colorText(hdc uintptr, col uint32) uintptr {
	pSetTextColor.Call(hdc, uintptr(col))
	pSetBkColor.Call(hdc, uintptr(rgb(255, 255, 255)))
	return g.white
}

func (g *gui) notify(p unsafe.Pointer) (uintptr, bool) {
	hdr := (*NMHDR)(p)
	if hdr.HwndFrom != g.ctl[idPortList] {
		return 0, false
	}
	switch hdr.Code {
	case NM_CUSTOMDRAW:
		cd := (*NMLVCUSTOMDRAW)(p)
		switch cd.Nmcd.DrawStage {
		case CDDS_PREPAINT:
			return CDRF_NOTIFYITEMDRAW, true
		case CDDS_ITEMPREPAINT:
			return CDRF_NOTIFYSUBITEMDRAW, true
		case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
			if cd.ISubItem == 2 {
				cd.ClrText = stateColors[Level(cd.Nmcd.ItemlParam)]
				pSelectObject.Call(cd.Nmcd.Hdc, g.bold)
			} else {
				cd.ClrText = rgb(33, 37, 41)
				pSelectObject.Call(cd.Nmcd.Hdc, g.font)
			}
			return CDRF_NEWFONT, true
		}
		return CDRF_DODEFAULT, true
	case LVN_ITEMCHANGED:
		g.readSelection()
		enable(g.ctl[idRemovePort], !g.busy && !g.view.Unknown && g.selKey != "")
		return 0, true
	case LVN_KEYDOWN:
		kd := (*NMLVKEYDOWN)(p)
		if kd.VKey == VK_DELETE && isEnabled(g.ctl[idRemovePort]) {
			g.command(idRemovePort, BN_CLICKED)
		}
		return 0, true
	}
	return 0, false
}

func (g *gui) command(id, code int) {
	if g.busy {
		return
	}
	if id >= idSlotButton && id < idSlotButton+maxRows {
		i := id - idSlotButton
		if i < len(g.view.Problems) && g.view.Problems[i].Button != "" {
			p := g.view.Problems[i]
			g.work(func() { g.app.Fix(p) })
		}
		return
	}
	switch id {
	case IDOK: // Enter key: act on the focused control only
		focus, _, _ := pGetFocus.Call()
		cb := g.ctl[idPortCombo]
		if parent, _, _ := pGetParent.Call(focus); focus == cb || parent == cb {
			g.command(idAdd, BN_CLICKED)
			return
		}
		if focus == g.ctl[idProtoCombo] {
			g.command(idAdd, BN_CLICKED)
			return
		}
		if focus == g.ctl[idCountCombo] {
			g.command(idAddCountry, BN_CLICKED)
			return
		}
		for _, bid := range append([]int{idMain, idAdd, idAddApp, idRemovePort, idAddCountry, idRemCountry, idLang}, secondIDs...) {
			if focus == g.ctl[bid] {
				g.command(bid, BN_CLICKED)
				return
			}
		}
		for i := 0; i < maxRows; i++ {
			if focus == g.ctl[idSlotButton+i] {
				g.command(idSlotButton+i, BN_CLICKED)
				return
			}
		}
	case idMain:
		// the second click of a double click on «بازگشت» lands here: ignore it
		now, _, _ := pGetTickCount.Call()
		dbl, _, _ := pGetDoubleClickTime.Call()
		if g.backAt != 0 && now-g.backAt < dbl {
			return
		}
		if g.view.Action != ActDisabled {
			g.work(g.app.Main)
		}
	case idLang:
		g.switchLanguage()
	case idOff:
		g.work(g.app.TurnOff)
	case idRefresh:
		if g.details {
			g.work(g.app.Details)
			return
		}
		g.work(func() { g.app.Refresh() })
	case idDetails:
		g.toggleDetails()
	case idCopy:
		if g.copyText(getText(g.ctl[idLog])) {
			messageBox(g.hwnd, T("متن جزئیات فنی کپی شد. حالا می‌توانید آن را در ایمیل یا پیام‌رسان Paste کنید."), appTitle(), MB_OK|MB_ICONINFO)
		} else {
			messageBox(g.hwnd, T("کپی انجام نشد (شاید برنامه‌ی دیگری Clipboard را در اختیار دارد). چند لحظه بعد دوباره امتحان کنید."), appTitle(), MB_OK|MB_ICONWARNING)
		}
	case idPortCombo:
		if code == CBN_SELCHANGE {
			cb := g.ctl[idPortCombo]
			i := int(int32(sendMessage(cb, CB_GETCURSEL, 0, 0)))
			if i >= 0 && i < len(wellKnown) {
				k := wellKnown[i]
				n := fmt.Sprint(k.Port)
				proto := uintptr(0)
				if k.Kind == KindUDP {
					proto = 1
				}
				sendMessage(g.ctl[idProtoCombo], CB_SETCURSEL, proto, 0)
				// the combo box writes the full line after this message: replace it afterwards
				g.do(func() { setText(cb, n); sendMessage(cb, CB_SETEDITSEL, 0, 0xFFFF0000) })
			}
		}
	case idCountList:
		if code == LBN_SELCHANGE {
			i := int(int32(sendMessage(g.ctl[idCountList], LB_GETCURSEL, 0, 0)))
			g.selCC = ""
			if i >= 0 && i < len(g.ccShown) {
				g.selCC = g.ccShown[i]
			}
			enable(g.ctl[idRemCountry], !g.busy && !g.view.Unknown && g.selCC != "")
		}
	case idAdd:
		text := getText(g.ctl[idPortCombo])
		if strings.TrimSpace(text) == "" {
			messageBox(g.hwnd, T("اول شماره‌ی پورت را در کادر «افزودن پورت» بنویسید یا از لیست آن انتخاب کنید."), appTitle(), MB_OK|MB_ICONINFO)
			pSetFocus.Call(g.ctl[idPortCombo])
			return
		}
		proto := "TCP"
		if sendMessage(g.ctl[idProtoCombo], CB_GETCURSEL, 0, 0) == 1 {
			proto = "UDP"
		}
		cb := g.ctl[idPortCombo]
		g.work(func() {
			if g.app.AddPort(text, proto) {
				g.do(func() { setText(cb, "") }) // keep what was typed when it was refused
			}
		})
	case idAddApp:
		path := g.pickFile(true)
		if path == "" {
			return
		}
		g.work(func() { g.app.AddProgram(path) })
	case idRemovePort:
		k := g.selKey
		if k == "" || g.view.Unknown {
			return
		}
		g.work(func() { g.app.RemoveEntry(k) })
	case idAddCountry:
		i := int(int32(sendMessage(g.ctl[idCountCombo], CB_GETCURSEL, 0, 0)))
		if i < 0 || i >= len(g.ccOrder) {
			messageBox(g.hwnd, T("اول یک کشور را از لیست انتخاب کنید."), appTitle(), MB_OK|MB_ICONINFO)
			pSetFocus.Call(g.ctl[idCountCombo])
			return
		}
		code := g.ccOrder[i]
		g.work(func() { g.app.AddCountry(code) })
	case idRemCountry:
		code := g.selCC
		if code == "" || g.view.Unknown {
			return
		}
		g.work(func() { g.app.RemoveCountry(code) })
	}
}

func (g *gui) loop() {
	var m MSG
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		if d, _, _ := pIsDialogMessageW.Call(g.hwnd, uintptr(unsafe.Pointer(&m))); d != 0 {
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// rtlText starts every line that has Persian in it with a right-to-left
// mark, so Windows (also with an English interface) keeps the reading order
// right when the line begins with an English word.
func rtlText(s string) string {
	if lang != "fa" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		for _, r := range l {
			if r >= 0x0600 && r <= 0x06FF {
				lines[i] = "\u200F" + l
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

func setRTL(h uintptr, s string) { setText(h, rtlText(s)) }

// system32dir: explorer.exe lives in the Windows folder itself.
func system32dir(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return root + `\` + name
}

// switchLanguage saves the other language and opens the program again in it
// (the window layout itself changes between right-to-left and left-to-right).
func (g *gui) switchLanguage() {
	next := "en"
	if lang == "en" {
		next = "fa"
	}
	if err := g.app.core.SaveLang(next); err != nil {
		messageBox(g.hwnd, err.Error(), appTitle(), MB_OK|MB_ICONERROR)
		return
	}
	self, err := os.Executable()
	if err != nil {
		messageBox(g.hwnd, err.Error(), appTitle(), MB_OK|MB_ICONERROR)
		return
	}
	r, _, _ := pShellExecuteW.Call(g.hwnd, uintptr(unsafe.Pointer(u16("open"))), uintptr(unsafe.Pointer(u16(self))),
		uintptr(unsafe.Pointer(u16("--restart"))), 0, 1)
	if r <= 32 {
		messageBox(g.hwnd, T("برنامه دوباره باز نشد. آن را ببندید و خودتان دوباره باز کنید."), appTitle(), MB_OK|MB_ICONWARNING)
		return
	}
	pDestroyWindow.Call(g.hwnd)
}

func rtlDrawFlag() uintptr {
	if lang == "fa" {
		return DT_RTLREADING
	}
	return 0
}
