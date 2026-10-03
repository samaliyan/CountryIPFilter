package main

// Turns the raw firewall state into what the window shows: one headline,
// one main button, the chosen countries, a table of ports and programs, and
// a short list of problems, each with the one button that fixes it.
//
// Wording rule: technical words stay in English (Windows Firewall, Rule,
// Group Policy, Remote Desktop, IP, VPN); explanations are short Persian.
// Numbers are written with Latin digits everywhere.

import (
	"fmt"
	"strings"
	"time"
)

type FixKind int

const (
	FixNone       FixKind = iota // nothing the program can do (explained in the text)
	FixFirewall                  // switch the Windows Firewall on
	FixReapply                   // write the settings of our rules again (ports, on, TCP ...)
	FixCloseRule                 // switch off one old rule (safe)
	FixCloseBroad                // switch off one old rule that may also cut other services (asks with a warning)
	FixManualList                // get the country lists by hand
	FixAutoUpdate                // switch on (or renew) the monthly update
	FixBlockRule                 // switch off a Block rule that shuts our port for everyone
	FixUpdateList                // download the country lists now and rewrite the rules
	FixMigrate                   // move the rules of version 3 to this version
)

// autoFixable: may run inside "fix all problems" after one confirmation.
func autoFixable(k FixKind) bool {
	switch k {
	case FixFirewall, FixReapply, FixCloseRule, FixAutoUpdate, FixBlockRule, FixUpdateList, FixMigrate:
		return true
	}
	return false
}

type Problem struct {
	Text   string
	Button string // empty: no button
	Kind   FixKind
	Rule   Conflict
	Severe bool   // red: protection does not work
	Step   string // one line for the "fix all" confirmation
}

// MainAction is what the big button does.
type MainAction int

const (
	ActRefresh  MainAction = iota // read the state again
	ActTurnOn                     // switch protection on
	ActFixAll                     // fix every problem that needs no separate decision
	ActDisabled                   // nothing can be done here (Group Policy)
)

type PortRow struct {
	Key     string
	Item    string // "TCP 808", "UDP 1194", "Program"
	Service string
	State   string
	Level   Level
}

type View struct {
	Unknown   bool // the firewall could not be read
	On        bool
	Level     Level
	Title     string
	Desc      string
	Main      string
	Action    MainAction
	CanOff    bool // show "turn protection off"
	Entries   []Entry
	Countries []string
	Rows      []PortRow
	Problems  []Problem
	Info      string
}

type ViewInput struct {
	St          Status
	Entries     []Entry
	Countries   []string
	FetchFailed bool
	Now         time.Time
	// the program is not in a folder of its own, so the folder could not be
	// locked: anyone could replace the program file
	FolderShared bool
	// the program folder is its own, but locking it failed
	FolderLockFailed bool
}

const (
	MainOn    = "روشن کردن محافظت"
	MainOff   = "خاموش کردن محافظت"
	MainFix   = "درست کردن مشکل‌ها"
	MainCheck = "بررسی دوباره"

	GreenState   = "فقط کشورهای انتخاب‌شده"
	OpenState    = "باز برای همه"
	FwOpenState  = "باز برای همه (Firewall کار نمی‌کند)"
	ShutState    = "بسته، حتی برای کشورهای انتخاب‌شده"
	GPState      = "محافظت اثر ندارد (Group Policy)"
	SomeIPsState = "باز برای چند IP مشخص"
	ClosedState  = "بسته"
	UnknownState = "نامشخص"

	vpnNote = "کاربرانی که VPN روشن دارند و IP آن‌ها از کشور دیگری است، وصل نمی‌شوند."
)

// itemsWord: "these ports" or "these ports and programs".
func itemsWord(entries []Entry) string {
	if len(appsOf(entries)) > 0 {
		return T("این پورت‌ها و برنامه‌ها")
	}
	return T("این پورت‌ها")
}

// keyText: one entry inside a sentence: "port 808", "port UDP 1194",
// "the program RevitServer.exe".
func keyText(key string, entries []Entry) string {
	e, ok := entryOfKey(key, entries)
	if !ok {
		return ltr(key)
	}
	if e.Kind == KindApp {
		return T("برنامه‌ی %s", e.Short())
	}
	return T("پورت %s", e.Short())
}

func keysText(keys []string, entries []Entry) string {
	var out []string
	for _, k := range keys {
		out = append(out, keyText(k, entries))
	}
	return strings.Join(out, listSep())
}

// entryOfKey finds the entry (with its spelling) for a key.
func entryOfKey(key string, entries []Entry) (Entry, bool) {
	for _, e := range entries {
		if e.Key() == key {
			return e, true
		}
	}
	if p, ok := strings.CutPrefix(key, "app:"); ok {
		return AppEntry(p), true
	}
	if p, ok := strings.CutPrefix(key, "udp:"); ok {
		e, ok := ParseEntry("UDP " + p)
		return e, ok
	}
	return ParseEntry(key)
}

func Assess(in ViewInput) View {
	st, entries := in.St, in.Entries
	v := View{On: len(st.Ours) > 0, Entries: entries, Countries: in.Countries}
	cc := countriesText(in.Countries)
	what := itemsWord(entries)

	openKeys, someKeys, blocked := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, c := range st.Conflicts {
		for _, k := range c.Covers {
			switch {
			case c.Enabled && c.Open:
				openKeys[k] = true
			case c.Enabled:
				someKeys[k] = true
			}
		}
	}
	for _, c := range st.Blocks {
		for _, k := range c.Covers {
			blocked[k] = true
		}
	}
	// rules of version 3 still there: they let Iran in on their ports, and
	// someone may have opened them to everyone
	for _, r := range st.Old {
		if r.Enabled && r.Wide {
			for _, p := range r.Ports {
				openKeys[TCP(p).Key()] = true
			}
		}
	}
	gp := st.LocalRulesBlocked()
	fwBad := st.FirewallProblem() && !gp
	inBlocked := st.InboundBlocked() && !gp && !fwBad

	// ---- rows first: the headline is built from what they say
	worldOpen, ownShut := false, false
	for _, e := range entries {
		k := e.Key()
		r := PortRow{Key: k, Item: e.Label(), Service: serviceName(e, st)}
		switch {
		case fwBad:
			r.State, r.Level = FwOpenState, LevelRed
		case v.On && gp:
			r.State, r.Level = GPState, LevelRed
		case v.On && inBlocked:
			r.State, r.Level = ShutState, LevelRed
		case openKeys[k] || (v.On && st.wideFor(e)):
			r.State, r.Level = OpenState, LevelRed
		case !v.On && someKeys[k]:
			r.State, r.Level = SomeIPsState, LevelGrey
		case !v.On:
			r.State, r.Level = ClosedState, LevelGrey
		case blocked[k] || !st.covers(e):
			r.State, r.Level = ShutState, LevelRed
		default:
			r.State, r.Level = GreenState, LevelGreen
		}
		worldOpen = worldOpen || r.State == OpenState || r.State == FwOpenState
		ownShut = ownShut || r.State == ShutState || r.State == GPState
		v.Rows = append(v.Rows, r)
	}
	allGreen := !worldOpen && !ownShut

	// ---- problems, most important first
	add := func(p Problem) { v.Problems = append(v.Problems, p) }
	if gp {
		add(Problem{Text: T("Group Policy اجازه نمی‌دهد Rule های این کامپیوتر کار کنند، پس محافظت اثری ندارد.") + nl + T("فقط مدیر دامنه (Domain Admin) می‌تواند این را درست کند."), Severe: v.On})
	} else if fwBad && v.On {
		add(Problem{Text: fwWhy(st) + " " + T("تا درست نشود، همه‌ی پورت‌ها برای همه‌ی دنیا باز هستند."), Button: T("روشن کردن Firewall"), Kind: FixFirewall, Severe: true, Step: T("روشن کردن Windows Firewall")})
	} else if inBlocked && v.On {
		add(Problem{Text: T("در Windows Firewall گزینه‌ی %s روشن است؛ پس هیچ Rule (حتی Rule های محافظت) اثر ندارد و کاربران کشورهای انتخاب‌شده هم وصل نمی‌شوند.", ltr("Block all incoming connections")), Button: T("درست کردن Firewall"), Kind: FixFirewall, Severe: true, Step: T("خاموش کردن گزینه‌ی Block all incoming connections")})
	} else if off := st.InactiveOff(); len(off) > 0 && v.On {
		text := T("Windows Firewall در Profile %s خاموش است. این Profile الان استفاده نمی‌شود، ولی اگر Network Profile سرور عوض شود، محافظت اثری ندارد.", ltr(off[0]))
		if len(off) > 1 {
			text = T("Windows Firewall در Profile های %s خاموش است. این Profile ها الان استفاده نمی‌شوند، ولی اگر Network Profile سرور عوض شود، محافظت اثری ندارد.", ltr(strings.Join(off, ", ")))
		}
		add(Problem{Text: text, Button: T("روشن کردن Firewall"), Kind: FixFirewall, Step: T("روشن کردن Windows Firewall در همه‌ی Profile ها")})
	}
	if len(st.Old) > 0 {
		add(Problem{Text: T("Rule های نسخه‌ی قدیمی این برنامه (%s) هنوز هستند و به این نسخه منتقل نشدند. تا وقتی هستند، پورت‌هایشان برای IP های ایران باز است، هر کشوری که اینجا انتخاب شده باشد.", ltr(OldGroup)), Button: T("انتقال Rule ها"), Kind: FixMigrate, Severe: true, Step: T("انتقال Rule های نسخه‌ی قدیمی به این نسخه")})
	}
	if in.FetchFailed {
		add(Problem{Text: T("لیست IP کشورها از اینترنت دانلود نشد (شاید اینترنت این سرور محدود است). می‌توانید لیست را دستی بگیرید."), Button: T("دریافت دستی لیست"), Kind: FixManualList})
	}
	if v.On {
		if !st.RulesMatch(entries) {
			text := T("Rule های محافظت با لیست پورت‌ها و برنامه‌ها یکی نیستند، یا کسی تنظیمات آن‌ها را دستی تغییر داده.")
			if !st.Repairable() {
				text = T("بخشی از Rule های محافظت پاک شده یا IP های آن‌ها دستی تغییر کرده. باید با لیست تازه‌ی IP کشورها دوباره نوشته شوند.")
			}
			add(Problem{Text: text, Button: T("نوشتن دوباره‌ی Rule ها"), Kind: FixReapply, Severe: !allGreen || !st.Repairable(), Step: T("نوشتن دوباره‌ی Rule های محافظت")})
		}
		if len(in.Countries) > 0 && !sameStrings(in.Countries, st.Tags.Countries) {
			extra := false
			for _, c := range st.Tags.Countries {
				extra = extra || !containsStr(in.Countries, c)
			}
			add(Problem{Text: T("Rule های محافظت برای این کشورها نوشته شده‌اند: %s. ولی کشورهای انتخاب‌شده این‌ها هستند: %s.", countriesText(st.Tags.Countries), cc),
				Button: T("به‌روزرسانی لیست"), Kind: FixUpdateList, Severe: extra || len(st.Tags.Countries) == 0, Step: T("دانلود لیست IP کشورهای انتخاب‌شده")})
		}
		for _, c := range st.Dangerous() {
			name := nl + ltr("Rule:  "+short(c.Display, 60))
			what := keysText(c.Covers, entries)
			risky := st.Sensitive(c.Covers)
			switch {
			case !c.Local:
				add(Problem{Text: T("یک Rule %s، %s را برای همه باز گذاشته.", sourceText(c.Source), what) + " " + sourceFix(c.Source) + name, Severe: true})
			case len(risky) > 0:
				add(Problem{Text: T("یک Rule، %s را برای همه باز گذاشته. چون این برای %s است، خاموش کردنش ممکن است اتصال خود شما را قطع کند.", what, st.sensitiveNames(risky)) + name, Button: T("خاموش کردن Rule"), Kind: FixCloseBroad, Rule: c, Severe: true})
			case c.Broad && c.Program != "" && !strings.EqualFold(c.Program, "System") && !strings.Contains(strings.ToLower(c.Program), "svchost"):
				add(Problem{Text: T("یک Rule قدیمی، همه‌ی پورت‌های برنامه‌ی %s (از جمله %s) را برای همه باز گذاشته. خاموش کردنش ممکن است بقیه‌ی کارهای این برنامه را هم قطع کند.", ltr(baseName(c.Program)), what) + name, Button: T("خاموش کردن Rule"), Kind: FixCloseBroad, Rule: c, Severe: true})
			case c.Broad:
				add(Problem{Text: T("یک Rule قدیمی، %s و پورت‌های دیگری را برای همه باز گذاشته. خاموش کردنش ممکن است سرویس‌های دیگر (مثلاً Remote Desktop) را هم قطع کند.", what) + name, Button: T("خاموش کردن Rule"), Kind: FixCloseBroad, Rule: c, Severe: true})
			default:
				add(Problem{Text: T("یک Rule قدیمی، %s را هنوز برای همه باز گذاشته.", what) + name, Button: T("خاموش کردن Rule"), Kind: FixCloseRule, Rule: c, Severe: true, Step: T("خاموش کردن Rule قدیمی:  %s", ltr(short(c.Display, 50)))})
			}
		}
		for _, c := range st.Blocks {
			name := nl + ltr("Rule:  "+short(c.Display, 60))
			what := keysText(c.Covers, entries)
			if !c.Local {
				add(Problem{Text: T("یک Rule از نوع Block %s، %s را برای همه (حتی کشورهای انتخاب‌شده) بسته.", sourceText(c.Source), what) + " " + sourceFix(c.Source) + name, Severe: true})
				continue
			}
			add(Problem{Text: T("یک Rule از نوع Block، %s را برای همه (حتی کشورهای انتخاب‌شده) بسته، پس کاربران هم وصل نمی‌شوند.", what) + name, Button: T("خاموش کردن Rule"), Kind: FixBlockRule, Rule: c, Severe: true, Step: T("خاموش کردن Rule از نوع Block:  %s", ltr(short(c.Display, 50)))})
		}
		t := st.Tags
		listOld := !t.ListDate.IsZero() && in.Now.Sub(t.ListDate) > 60*24*time.Hour
		switch {
		case !t.LastWhen.IsZero() && !t.LastOK && !in.FetchFailed:
			add(Problem{Text: T("به‌روزرسانی لیست IP کشورها در تاریخ %s انجام نشد:", dateText(t.LastWhen)) + " " + failWhy(t.LastWhy), Button: T("به‌روزرسانی لیست"), Kind: FixUpdateList, Step: T("دانلود لیست تازه‌ی IP کشورها")})
		case listOld && !in.FetchFailed:
			add(Problem{Text: T("لیست IP کشورها بیش از دو ماه است به‌روز نشده."), Button: T("به‌روزرسانی لیست"), Kind: FixUpdateList, Step: T("دانلود لیست تازه‌ی IP کشورها")})
		}
		switch {
		case !st.Task:
			add(Problem{Text: T("به‌روزرسانی خودکار لیست IP کشورها (هر 4 هفته یک بار) خاموش است."), Button: T("روشن کردن به‌روزرسانی"), Kind: FixAutoUpdate, Step: T("روشن کردن به‌روزرسانی خودکار")})
		case !st.TaskCurrent():
			add(Problem{Text: T("به‌روزرسانی خودکار با یک نسخه‌ی قدیمی تنظیم شده و باید دوباره تنظیم شود."), Button: T("تنظیم دوباره"), Kind: FixAutoUpdate, Step: T("تنظیم دوباره‌ی به‌روزرسانی خودکار")})
		case st.TaskFailed():
			add(Problem{Text: T("به‌روزرسانی خودکار در تاریخ %s اجرا نشد (کد خطای Windows: %s). شاید Group Policy اجرای Script های PowerShell را بسته. تا آن موقع، لیست را با دکمه‌ی «%s» دستی به‌روز کنید.", dateText(st.TaskRun), ltr(fmt.Sprintf("0x%X", st.TaskCode)), T("به‌روزرسانی لیست")), Button: T("به‌روزرسانی لیست"), Kind: FixUpdateList, Step: T("دانلود لیست تازه‌ی IP کشورها")})
		}
	}

	if in.FolderLockFailed && !in.FolderShared {
		add(Problem{Text: T("Permission های پوشه‌ی برنامه محدود نشد، پس کاربران دیگر شاید بتوانند فایل برنامه را عوض کنند. علت در «جزئیات فنی» نوشته شده.")})
	}
	if in.FolderShared {
		add(Problem{Text: T("برنامه نصب نشده و در پوشه‌ی جدای خودش نیست، پس کاربران دیگر می‌توانند فایل برنامه را عوض کنند.") + nl + T("برای نصب: برنامه را ببندید، دوباره باز کنید و به سؤال نصب جواب Yes بدهید.")})
	}

	severe, fixable := false, false
	for _, p := range v.Problems {
		severe = severe || p.Severe
		fixable = fixable || autoFixable(p.Kind)
	}

	// ---- headline and main button (Main is a key: the window translates it)
	switch {
	case !v.On:
		v.Level = LevelGrey
		v.Title = T("محافظت خاموش است")
		v.Main, v.Action = MainOn, ActTurnOn
		switch {
		case gp:
			v.Action = ActDisabled
			v.Desc = T("Group Policy اجازه نمی‌دهد محافظت روی این کامپیوتر کار کند.")
		case len(in.Countries) == 0 || len(entries) == 0:
			v.Desc = T("اول در پایین دست‌کم یک کشور و یک پورت (یا برنامه) انتخاب کنید، بعد «%s» را بزنید.", T(MainOn))
			if fwBad || worldOpen {
				v.Level = LevelOrange
			}
		case fwBad:
			v.Level = LevelOrange
			v.Desc = fwWhy(st) + " " + T("الان همه‌ی دنیا می‌توانند به %s وصل شوند. با «%s»، Firewall روشن می‌شود و فقط IP های %s وصل می‌شوند.", what, T(MainOn), cc)
		case worldOpen:
			v.Level = LevelOrange
			v.Desc = T("الان همه‌ی دنیا می‌توانند به %s وصل شوند. با «%s»، فقط IP های %s وصل می‌شوند.", what, T(MainOn), cc)
		default:
			v.Desc = T("با «%s»، %s فقط برای IP های %s باز می‌شوند.", T(MainOn), what, cc)
		}
	case severe:
		v.Level = LevelRed
		v.Title = T("محافظت کامل کار نمی‌کند")
		switch {
		case worldOpen:
			v.Desc = T("هنوز از کشورهای دیگر هم می‌شود به %s وصل شد.", what)
		case ownShut:
			v.Desc = T("بعضی موردها حتی برای کشورهای انتخاب‌شده هم بسته‌اند.")
		default:
			v.Desc = T("تنظیمات محافظت کامل نیست.")
		}
	case len(v.Problems) > 0:
		v.Level = LevelOrange
		v.Title = T("محافظت روشن است")
		if len(v.Problems) == 1 {
			v.Desc = T("محافظت کار می‌کند، ولی یک مورد در پایین هست که بهتر است درست شود.")
		} else {
			v.Desc = T("محافظت کار می‌کند، ولی %d مورد در پایین هست که بهتر است درست شوند.", len(v.Problems))
		}
	default:
		v.Level = LevelGreen
		v.Title = T("محافظت روشن است")
		v.Desc = T("فقط IP های %s به %s وصل می‌شوند.", cc, what) + " " + T(vpnNote)
	}
	if v.On {
		v.CanOff = true
		v.Main, v.Action = MainCheck, ActRefresh
		if fixable {
			v.Main, v.Action = MainFix, ActFixAll
			if v.Level == LevelRed {
				v.Desc += " " + T("دکمه‌ی «%s» را بزنید.", T(MainFix))
			}
		} else if severe {
			v.Desc += " " + T("راه درست کردن هر مورد در پایین نوشته شده.")
		}
	}

	// ---- small info line
	var info []string
	switch {
	case v.On && st.Tags.ListDate.IsZero():
		info = append(info, T("لیست IP: %s", rangesText(st.ourTotal())))
	case v.On:
		info = append(info, T("لیست IP: %s، به‌روز شده در %s", rangesText(st.ourTotal()), dateText(st.Tags.ListDate)))
	default:
		info = append(info, T("لیست IP: هنگام روشن کردن دانلود می‌شود"))
	}
	if v.On {
		if st.Task {
			info = append(info, T("به‌روزرسانی خودکار: روشن"))
		} else {
			info = append(info, T("به‌روزرسانی خودکار: خاموش"))
		}
	}
	if !in.Now.IsZero() {
		info = append(info, T("آخرین بررسی: %s", ltr(in.Now.Format("15:04"))))
	}
	v.Info = strings.Join(info, "   •   ")
	return v
}

func failWhy(code string) string {
	switch code {
	case "download":
		return T("لیست از اینترنت دانلود نشد.")
	case "list":
		return T("لیست دانلودشده ناقص یا نادرست بود و استفاده نشد.")
	case "apply":
		return T("نوشتن Rule ها انجام نشد.")
	case "lock":
		return T("برنامه هم‌زمان در حال تغییر Rule ها بود؛ دفعه‌ی بعد دوباره امتحان می‌شود.")
	case "ports":
		return T("پورت‌ها یا برنامه‌های Rule های محافظت دستی تغییر کرده بودند؛ «%s» را بزنید.", T("نوشتن دوباره‌ی Rule ها"))
	}
	return T("خطای نامشخص.")
}

// sourceText: where a rule that is not stored on this computer comes from.
func sourceText(src string) string {
	switch strings.ToLower(src) {
	case "grouppolicy":
		return T("از Group Policy")
	case "mdm":
		return T("از MDM (مدیریت مرکزی)")
	}
	return T("سیستمی (%s)", ltr("Source: "+src))
}

func sourceFix(src string) string {
	switch strings.ToLower(src) {
	case "grouppolicy":
		return T("فقط مدیر دامنه (Domain Admin) می‌تواند آن را تغییر دهد.")
	case "mdm":
		return T("فقط مدیر سیستم مدیریت مرکزی می‌تواند آن را تغییر دهد.")
	}
	return T("این برنامه نمی‌تواند آن را تغییر دهد.")
}

// UnknownView: the firewall could not be read.
func UnknownView(entries []Entry, countries []string, on bool) View {
	v := View{Unknown: true, On: on, Level: LevelRed, Entries: entries, Countries: countries,
		Title: T("وضعیت خوانده نشد"),
		Desc:  T("برنامه نتوانست تنظیمات Windows Firewall را بخواند (شاید سرویس Windows Firewall متوقف است). «%s» را بزنید.", T(MainCheck)),
		Main:  MainCheck, Action: ActRefresh,
		Info: T("متن خطا در «جزئیات فنی» هست.")}
	for _, e := range entries {
		v.Rows = append(v.Rows, PortRow{Key: e.Key(), Item: e.Label(), Service: serviceName(e, Status{}), State: UnknownState, Level: LevelGrey})
	}
	return v
}

func fwWhy(st Status) string {
	if st.FirewallOff() {
		return T("Windows Firewall خاموش است.")
	}
	return T("Windows Firewall روشن است ولی هر اتصال Inbound را قبول می‌کند (%s).", ltr("Default inbound: Allow"))
}

// serviceName: the known name, else what is listening on the port; for a
// program its file name.
func serviceName(e Entry, st Status) string {
	if e.Kind == KindApp {
		return baseName(e.Path)
	}
	if n := knownName(e.Kind, e.Port); n != "" {
		return n
	}
	return st.ListenerName(e.Kind, e.Port)
}

func short(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// jalali formats a date in the Iranian calendar, e.g. 1405/07/04.
func jalali(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	t = t.In(time.FixedZone("IRST", 3*3600+1800))
	gy, gm, gd := t.Year(), int(t.Month()), t.Day()
	gdm := []int{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}
	gy2 := gy
	if gm > 2 {
		gy2 = gy + 1
	}
	days := 355666 + 365*gy + (gy2+3)/4 - (gy2+99)/100 + (gy2+399)/400 + gd + gdm[gm-1]
	jy := -1595 + 33*(days/12053)
	days %= 12053
	jy += 4 * (days / 1461)
	days %= 1461
	if days > 365 {
		jy += (days - 1) / 365
		days = (days - 1) % 365
	}
	var jm, jd int
	if days < 186 {
		jm = 1 + days/31
		jd = 1 + days%31
	} else {
		jm = 7 + (days-186)/30
		jd = 1 + (days-186)%30
	}
	return ltr(fmt.Sprintf("%04d/%02d/%02d", jy, jm, jd))
}

// ltr keeps an English piece in its own left-to-right order inside Persian
// text (not needed when the window is in English).
func ltr(s string) string {
	if lang == "en" {
		return s
	}
	return "\u202A" + s + "\u202C"
}

// dateText: the Iranian calendar in Persian, ISO dates in English.
func dateText(t time.Time) string {
	if lang == "en" {
		if t.IsZero() {
			return ""
		}
		return t.Local().Format("2006-01-02")
	}
	return jalali(t)
}

// rangesText: "1966 IP ranges", kept in one piece inside Persian text.
func rangesText(n int) string {
	if lang == "en" {
		return fmt.Sprintf("%d IP ranges", n)
	}
	return ltr(fmt.Sprintf("%d IP range", n))
}
