package main

// What happens when the user presses a button. Independent of Windows so it
// can be tested; the window implements UI.
//
// Wording rule: technical words stay in English (Windows Firewall, Rule,
// Group Policy, Remote Desktop, IP, VPN); explanations are short Persian.

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type UI interface {
	Log(line string)
	Progress(step string)               // what is being done right now
	Ask(text string, warning bool) bool // Yes/No question, default No
	Tell(text string, level Level)      // information box
	Show(v View)
	OpenURL(url string) bool
	PickFile(program bool) string // a list file or a program (.exe); "" when cancelled
}

type App struct {
	core *Core
	ui   UI
	Now  func() time.Time

	// FolderShared: the program is not in a folder of its own, so the
	// folder was not locked; FolderLockFailed: locking it did not work
	FolderShared     bool
	FolderLockFailed bool

	fetchFailed  bool
	taskTried    bool     // the old monthly task was set up again once this session
	migrateTried bool     // moving the rules of version 3 was tried once this session
	oldTaskTried bool     // removing the monthly task of version 3 was tried once this session
	pending      *Lists   // lists picked by hand, not used yet
	pendingCC    []string // the countries of those lists
	last         Status
	lastOK       bool
	view         View
}

const (
	nl      = "\r\n"
	yesWord = "«Yes (بله)»"
	support = "در «جزئیات فنی» دکمه‌ی «کپی متن» را بزنید و متن را برای پشتیبانی بفرستید."
)

// log writes a line to the details view and log.txt, in the window's language.
func (a *App) log(format string, args ...any) { a.core.logf("%s", T(format, args...)) }

// logEn writes a technical English line that keeps its left-to-right order.
func (a *App) logEn(format string, args ...any) {
	a.core.logf("%s", ltr(fmt.Sprintf(format, args...)))
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *App) step(s string) { a.ui.Progress(T(s)) }

func (a *App) isOn() bool { return a.lastOK && len(a.last.Ours) > 0 }

func (a *App) entries() []Entry    { return a.core.LoadEntries() }
func (a *App) countries() []string { return a.core.LoadCountries() }

// ---------------------------------------------------------------- reading the state

// Refresh reads the firewall and redraws the window.
func (a *App) Refresh() (Status, bool) {
	a.step("خواندن تنظیمات Windows Firewall…")
	entries := a.entries()
	st, err := a.core.Status(entries)
	if err != nil {
		a.log("خواندن وضعیت Windows Firewall انجام نشد: %v", err)
		a.view = UnknownView(entries, a.countries(), len(a.last.Ours) > 0)
		a.ui.Show(a.view)
		a.lastOK = false
		return st, false
	}
	if a.housekeeping(st) {
		// what was just written must be what the next action starts from
		entries = a.entries()
		st2, err := a.core.Status(entries)
		if err != nil {
			a.log("خواندن وضعیت Windows Firewall انجام نشد: %v", err)
			a.view = UnknownView(entries, a.countries(), len(st.Ours) > 0)
			a.ui.Show(a.view)
			a.lastOK = false
			return st2, false
		}
		st = st2
	}
	a.last, a.lastOK = st, true
	a.view = Assess(a.input(st))
	a.ui.Show(a.view)
	return st, true
}

func (a *App) input(st Status) ViewInput {
	return ViewInput{St: st, Entries: a.entries(), Countries: a.countries(), FetchFailed: a.fetchFailed, Now: a.now(),
		FolderShared: a.FolderShared, FolderLockFailed: a.FolderLockFailed}
}

// housekeeping keeps the saved state in order. Returns true when it changed
// something that needs a new look at the firewall.
func (a *App) housekeeping(st Status) bool {
	changed := false
	if len(st.Old) > 0 && !a.migrateTried {
		a.migrateTried = true
		if a.migrate(st) {
			return true
		}
	}
	if st.OldTask && len(st.Old) == 0 && !a.oldTaskTried {
		a.oldTaskTried = true
		if err := a.core.RemoveOld(); err != nil {
			a.log("حذف به‌روزرسانی خودکار نسخه‌ی قدیمی انجام نشد: %v", err)
		} else {
			a.log("به‌روزرسانی خودکار نسخه‌ی قدیمی (%s) حذف شد", OldTask)
			changed = true
		}
	}
	on := len(st.Ours) > 0
	entries := a.entries()
	// the program was copied without its data folder: the rules know the rest
	if on && !a.core.HasPortsFile() {
		if e := st.OurEntries(); len(e) > 0 {
			a.saveEntriesFromRules(e)
			entries = e
			changed = true
		}
	}
	if on && !a.core.HasCountriesFile() && len(st.Tags.Countries) > 0 {
		if err := a.core.SaveCountries(st.Tags.Countries); err == nil {
			a.log("لیست کشورها از Rule های محافظت خوانده شد: %s", countriesText(st.Tags.Countries))
			changed = true
		}
	}
	tags := map[string]string{}
	// remember which programs serve our ports, for the times they are stopped
	if on {
		seen := map[string][]string{}
		for k, progs := range st.Tags.Seen {
			seen[k] = append(seen[k], progs...)
		}
		grew := false
		note := func(key, prog string) {
			if prog != "" && !containsFold(seen[key], prog) {
				seen[key] = append(seen[key], prog)
				grew = true
			}
		}
		for _, e := range entries {
			switch e.Kind {
			case KindTCP:
				for _, l := range st.Listeners[e.Port] {
					note(e.Key(), l.Program)
				}
			case KindUDP:
				for _, l := range st.UDP[e.Port] {
					note(e.Key(), l.Program)
				}
			case KindApp:
				// the TCP ports a program listens on, for the times it is stopped
				// (not UDP: programs also open short-lived UDP ports of their own)
				for _, p := range appPorts(e.Path, st.Listeners) {
					note(TCP(p).Key(), e.Path)
				}
			}
		}
		if grew && seenSize(seen) <= 200 {
			tags["SEEN"] = encodeSeen(seen)
		}
	}
	if on && st.Proxy != st.Tags.Raw["PROXY"] {
		tags["PROXY"] = st.Proxy
	}
	if len(tags) > 0 {
		if err := a.core.SetTags(tags); err != nil {
			a.log("ذخیره‌ی اطلاعات در Rule های محافظت انجام نشد: %v", err)
		} else {
			changed = true
		}
	}
	// the monthly task of an older version of this program: set it up again
	// with the current script, or remove it when protection is off
	if st.Task && !st.TaskCurrent() && !a.taskTried {
		a.taskTried = true
		if err := a.core.Schedule(on); err != nil {
			a.log("تنظیم دوباره‌ی به‌روزرسانی خودکار انجام نشد: %v", err)
		} else if on {
			a.log("به‌روزرسانی خودکار با نسخه‌ی فعلی دوباره تنظیم شد")
			changed = true
		} else {
			a.log("به‌روزرسانی خودکار قدیمی حذف شد (محافظت خاموش است)")
			changed = true
		}
	}
	return changed
}

// saveEntriesFromRules saves the entries read back from the rules.
func (a *App) saveEntriesFromRules(e []Entry) {
	if err := a.core.SaveEntries(e); err == nil {
		var names []string
		for _, x := range e {
			names = append(names, x.Short())
		}
		a.log("لیست پورت‌ها و برنامه‌ها از Rule های محافظت خوانده شد: %s", strings.Join(names, listSep()))
	}
}

// migrate moves the rules of version 3 ("Iran IP Filter": Iran only, TCP
// ports) to this version: same addresses, same ports, same records. Who can
// connect does not change. Returns true when something was changed.
func (a *App) migrate(st Status) bool {
	if st.Repairable() && st.RulesMatch(a.entries()) {
		// moved already (or protection was turned on again); the old rules are
		// left over. Their records go over first: without them a rule version 3
		// switched off would never come back.
		wrote, ok := a.keepOldRecords(st)
		if !ok {
			return false
		}
		// ports version 3 opened that are not in the list: ask before closing them
		var missing []int
		for _, r := range st.Old {
			for _, p := range r.Ports {
				if !hasEntry(a.entries(), TCP(p).Key()) && !containsInt(missing, p) {
					missing = append(missing, p)
				}
			}
		}
		if len(missing) > 0 {
			sort.Ints(missing)
			if a.ui.Ask(T("نسخه‌ی قدیمی این پورت‌ها را هم برای ایران باز کرده بود: %s", strings.Join(portList(missing), listSep()))+nl+nl+
				T("این پورت‌ها به لیست اضافه شوند؟ اگر No را بزنید، بعد از حذف Rule های نسخه‌ی قدیمی بسته می‌شوند."), true) {
				var e []Entry
				for _, p := range missing {
					e = append(e, TCP(p))
				}
				a.core.SaveEntries(append(a.entries(), e...))
				a.log("پورت‌های نسخه‌ی قدیمی به لیست اضافه شدند: %s", strings.Join(portList(missing), listSep()))
				return true // the rules are written for them first; the old ones go after that
			}
		}
		if err := a.core.RemoveOld(); err != nil {
			a.log("حذف Rule های نسخه‌ی قدیمی انجام نشد: %v", err)
			return wrote
		}
		a.log("Rule های نسخه‌ی قدیمی (%s) حذف شدند", OldGroup)
		return true
	}
	if len(st.Ours) > 0 {
		// rules of this version exist but need writing again (that is a
		// problem of its own on the screen): never overwrite them with the
		// Iran-only list of version 3. Keep the old records now; the old rules
		// go once the new ones are whole again.
		wrote, _ := a.keepOldRecords(st)
		return wrote
	}
	old := append([]OurRule(nil), st.Old...)
	sort.Slice(old, func(i, j int) bool { return old[i].Name < old[j].Name })
	var addrs []string
	var ports []int
	refuse := func(why string) bool {
		a.log("%s", why)
		a.ui.Tell(why+nl+nl+T("Rule های %s را در Windows Firewall بررسی کنید، یا نسخه‌ی قدیمی را باز کنید و محافظت را با آن خاموش کنید.", ltr(OldGroup)), LevelOrange)
		return false
	}
	for _, r := range old {
		if r.Wide {
			return refuse(T("Rule های نسخه‌ی قدیمی دستی تغییر کرده‌اند؛ منتقل نشدند"))
		}
		addrs = append(addrs, r.Addrs...)
		ports = append(ports, r.Ports...)
	}
	ranges := Aggregate(addrs)
	ports = uniqInts(ports)
	if len(ranges) == 0 || len(ports) == 0 {
		return refuse(T("Rule های نسخه‌ی قدیمی IP یا پورت ندارند؛ منتقل نشدند"))
	}
	if err := checkTotal(ranges); err != nil {
		return refuse(T("Rule های نسخه‌ی قدیمی منتقل نشدند:") + " " + err.Error())
	}
	var entries []Entry
	for _, p := range ports {
		entries = append(entries, TCP(p))
	}
	a.log("—— انتقال Rule های نسخه‌ی قدیمی (%s) به این نسخه", OldGroup)
	a.step("انتقال Rule های نسخه‌ی قدیمی…")
	ot := st.OldTags
	when := ot.ListDate
	if when.IsZero() {
		when = a.now()
	}
	tags := map[string]string{
		"OK":  fmt.Sprintf("%s,%d,%d", when.UTC().Format(time.RFC3339), len(ranges), addrTotal(ranges)),
		"CC":  "IR",
		"CCN": fmt.Sprintf("IR:%d", addrTotal(ranges)),
	}
	for _, k := range []string{"LAST", "OFF", "SEEN", "FWON", "PROXY"} {
		if v := ot.Raw[k]; v != "" {
			tags[k] = v
		}
	}
	if err := a.core.Migrate(ranges, entries, tags); err != nil {
		a.log("انتقال Rule های نسخه‌ی قدیمی انجام نشد: %v", err)
		return true // the new rules may exist now: look again
	}
	if !a.core.HasPortsFile() {
		a.core.SaveEntries(entries)
	}
	if !a.core.HasCountriesFile() {
		a.core.SaveCountries([]string{"IR"})
	}
	if err := a.core.Schedule(true); err != nil {
		a.log("روشن کردن به‌روزرسانی خودکار انجام نشد: %v", err)
	}
	a.log("Rule های نسخه‌ی قدیمی منتقل شدند: %s، کشور: %s", strings.Join(portList(ports), listSep()), CountryName("IR"))
	a.ui.Tell(T("Rule های نسخه‌ی قدیمی این برنامه (%s) به این نسخه منتقل شدند.", ltr(OldGroup))+nl+nl+
		T("چیزی برای کاربران عوض نشد: همان پورت‌ها همچنان فقط برای IP های %s باز هستند.", CountryName("IR")), LevelGreen)
	return true
}

// keepOldRecords copies what version 3 recorded (rules it switched off,
// that it switched the firewall on, programs seen) into our rules.
func (a *App) keepOldRecords(st Status) (wrote, ok bool) {
	ot := st.OldTags
	tags := map[string]string{}
	if len(ot.Off) > 0 {
		merged := mergeOff(append([]OffRule(nil), st.Tags.Off...), ot.Off)
		if enc := encodeOff(merged); enc != st.Tags.Raw["OFF"] {
			tags["OFF"] = enc
		}
	}
	if ot.FwOn && !st.Tags.FwOn {
		tags["FWON"] = "1"
	}
	if len(ot.Seen) > 0 {
		seen := map[string][]string{}
		for k, v := range st.Tags.Seen {
			seen[k] = append(seen[k], v...)
		}
		for k, v := range ot.Seen {
			for _, p := range v {
				if !containsFold(seen[k], p) {
					seen[k] = append(seen[k], p)
				}
			}
		}
		if enc := encodeSeen(seen); enc != st.Tags.Raw["SEEN"] {
			tags["SEEN"] = enc
		}
	}
	if len(tags) == 0 {
		return false, true
	}
	if err := a.core.SetTags(tags); err != nil {
		a.log("ذخیره‌ی اطلاعات در Rule های محافظت انجام نشد: %v", err)
		return false, false
	}
	return true, true
}

// forgetProgram drops the ports remembered for a program that is no longer in the list.
func (a *App) forgetProgram(path string, left []Entry) {
	seen := map[string][]string{}
	changed := false
	for k, progs := range a.last.Tags.Seen {
		for _, p := range progs {
			if samePath(p, path) && !hasEntry(left, k) {
				changed = true
				continue
			}
			seen[k] = append(seen[k], p)
		}
	}
	if changed {
		a.core.SetTags(map[string]string{"SEEN": encodeSeen(seen)})
	}
}

// remotePath: the file is on a network drive (set on Windows).
var remotePath = func(string) bool { return false }

func seenSize(m map[string][]string) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}

func mergeOff(list, more []OffRule) []OffRule {
	for _, m := range more {
		found := false
		for i := range list {
			if list[i].Name == m.Name {
				list[i].Covers = uniqStrings(append(list[i].Covers, m.Covers...))
				found = true
			}
		}
		if !found {
			list = append(list, OffRule{Name: m.Name, Covers: uniqStrings(m.Covers)})
		}
	}
	return list
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- technical details

// Details writes the technical picture: English lines, short Persian meaning.
func (a *App) Details() {
	st, ok := a.Refresh()
	entries, codes := a.entries(), a.countries()
	a.log("")
	a.log("==========  جزئیات فنی  ==========")
	a.logEn("    %s %s", AppName, Version)
	if !ok {
		a.log("وضعیت Windows Firewall خوانده نشد. متن خطا در خطوط بالا است.")
		return
	}

	a.log("")
	a.log("1)  Windows Firewall")
	var prof []string
	for _, p := range st.Profiles {
		state := "ON"
		if !p.Enabled {
			state = "OFF"
		}
		mark := ""
		if st.isActive(p.Name) {
			mark = " (active)"
		}
		prof = append(prof, fmt.Sprintf("%s%s: %s, inbound %s", p.Name, mark, state, p.Inbound))
	}
	a.logEn("    %s", strings.Join(prof, "   |   "))
	switch {
	case st.LocalRulesBlocked():
		a.log("    یعنی: Group Policy نمی‌گذارد Rule های این کامپیوتر اجرا شوند (مشکل دارد).")
	case st.FirewallProblem():
		a.log("    یعنی: Firewall خاموش است یا همه‌ی اتصال‌های Inbound را قبول می‌کند (مشکل دارد).")
	default:
		a.log("    یعنی: Firewall روشن است و هر اتصال Inbound که Rule نداشته باشد بسته است (درست است).")
	}

	a.log("")
	a.log("2)  Rule های محافظت")
	var items []string
	for _, e := range entries {
		if e.Kind == KindApp {
			items = append(items, "Program "+e.Path)
		} else {
			items = append(items, e.Kind+" "+fmt.Sprint(e.Port))
		}
	}
	a.logEn("    Countries: %s   |   Rule sets: %d   |   Rules: %d   |   IP ranges: %d", strings.Join(codes, ", "), len(st.sets()), len(st.Ours), st.ourTotal())
	a.logEn("    Ports and programs: %s", strings.Join(items, "   |   "))
	switch {
	case len(st.Ours) == 0:
		a.log("    یعنی: محافظت روشن نیست؛ هنوز هیچ Rule ساخته نشده.")
	case !st.RulesMatch(entries):
		a.log("    یعنی: Rule های محافظت هستند ولی ناقص‌اند یا دستی تغییر کرده‌اند (مشکل دارد).")
	default:
		a.log("    یعنی: این پورت‌ها و برنامه‌ها فقط برای %s باز هستند (درست است).", rangesText(st.ourTotal()))
	}
	if len(st.Tags.Countries) > 0 && !sameStrings(st.Tags.Countries, codes) {
		a.logEn("    Rules were written for: %s", strings.Join(st.Tags.Countries, ", "))
	}
	if !st.Tags.ListDate.IsZero() {
		a.logEn("    List downloaded: %s   |   %d addresses", st.Tags.ListDate.Local().Format("2006-01-02 15:04"), st.Tags.ListAddr)
	}
	if !st.Tags.LastWhen.IsZero() {
		res := "OK"
		if !st.Tags.LastOK {
			res = "FAILED"
		}
		a.logEn("    Last update: %s   |   %s   |   %s", st.Tags.LastWhen.Local().Format("2006-01-02 15:04"), res, st.Tags.LastWhy)
	}
	if len(st.Old) > 0 {
		a.logEn("    Rules of version 3 (%s): %d", OldGroup, len(st.Old))
	}

	a.log("")
	a.log("3)  برنامه‌هایی که روی این پورت‌ها کار می‌کنند")
	for _, e := range entries {
		switch e.Kind {
		case KindApp:
			t, u := appPorts(e.Path, st.Listeners), appPorts(e.Path, st.UDP)
			if len(t)+len(u) == 0 {
				a.logEn("    %s:  (not running or not listening now)", baseName(e.Path))
				continue
			}
			a.logEn("    %s:  TCP %s   |   UDP %s", baseName(e.Path), strings.Join(portList(t), ","), strings.Join(portList(u), ","))
		default:
			ls := st.Listeners[e.Port]
			if e.Kind == KindUDP {
				ls = st.UDP[e.Port]
			}
			if len(ls) == 0 {
				a.logEn("    %s %d:  (nothing is listening now)", e.Kind, e.Port)
				continue
			}
			for _, l := range ls {
				svc := ""
				if len(l.Services) > 0 {
					svc = "   |   Service: " + strings.Join(l.Services, ", ")
				}
				a.logEn("    %s %d:  %s%s", e.Kind, e.Port, l.Program, svc)
			}
		}
	}

	a.log("")
	a.log("4)  Rule های دیگری که همین پورت‌ها یا برنامه‌ها را باز یا بسته می‌کنند")
	off := offNames(st.Tags.Off)
	if len(st.Conflicts) == 0 && len(st.Blocks) == 0 {
		a.log("    هیچ (درست است).")
	}
	for _, c := range st.Conflicts {
		state := "OFF"
		if c.Enabled {
			state = "ON"
		}
		from := "Some IPs"
		if c.Open {
			from = "Everyone"
		}
		a.logEn("    • %s", c.Display)
		a.logEn("      Allow   |   %s   |   From: %s   |   For: %s   |   Source: %s", state, from, strings.Join(c.Covers, ", "), c.Source)
		switch {
		case c.Enabled && c.Open:
			a.log("      یعنی: این Rule برای همه‌ی دنیا باز است (در بخش «مشکل‌ها» هست).")
		case c.Enabled:
			a.log("      یعنی: فقط چند IP مشخص را راه می‌دهد (مشکلی ندارد).")
		case containsStr(off, c.Name):
			a.log("      یعنی: این برنامه خاموشش کرده؛ با «%s» دوباره روشن می‌شود.", T(MainOff))
		default:
			a.log("      یعنی: خاموش است و اثری ندارد.")
		}
		a.logEn("      %s", c.Tech)
	}
	for _, c := range st.Blocks {
		a.logEn("    • %s", c.Display)
		a.logEn("      Block   |   ON   |   From: Everyone   |   For: %s   |   Source: %s", strings.Join(c.Covers, ", "), c.Source)
		a.log("      یعنی: این Rule برای همه، حتی کشورهای انتخاب‌شده، بسته است (در بخش «مشکل‌ها» هست).")
	}

	a.log("")
	a.log("5)  به‌روزرسانی خودکار (Scheduled Task)")
	switch {
	case !st.Task:
		a.logEn("    OFF")
	case st.TaskCurrent():
		a.logEn("    ON   |   \"%s\"   |   every 4 weeks, Friday 04:00, as SYSTEM   |   runs PowerShell only", TaskName)
	default:
		a.logEn("    ON (old version)   |   %s", short(st.TaskArgs, 90))
	}

	a.log("")
	a.log("6)  نکته")
	a.log("    فقط IPv4 کشورها باز می‌شود؛ اتصال با IPv6 از بیرون بسته است.")
	a.logEn("    Source of the lists: %s", RipeURL("XX"))

	a.log("")
	a.log("7)  فایل‌های برنامه")
	a.logEn("    %s", a.core.Dir)
	a.log("    یعنی: فقط لیست کشورها (countries.txt)، پورت‌ها و برنامه‌ها (ports.txt)، زبان (settings.txt) و Log برنامه (log.txt) اینجاست؛ بقیه‌ی تنظیمات داخل خود Rule های Windows Firewall ذخیره می‌شوند.")

	a.log("")
	a.log("8)  همه‌ی مشکل‌ها")
	if len(a.view.Problems) == 0 {
		a.log("    هیچ.")
	}
	for i, p := range a.view.Problems {
		a.core.logf("    %d.  %s", i+1, strings.ReplaceAll(p.Text, nl, "   "))
	}
}

func offNames(list []OffRule) []string {
	var out []string
	for _, r := range list {
		out = append(out, r.Name)
	}
	return out
}

// ---------------------------------------------------------------- turning on

func (a *App) Main() {
	// decide from a fresh look, so the question lists what is true now; if
	// the button would now do something else, only show the new screen
	shown := a.view.Action
	if _, ok := a.Refresh(); !ok || a.view.Action != shown {
		return
	}
	switch a.view.Action {
	case ActTurnOn:
		a.TurnOn()
	case ActFixAll:
		a.FixAll()
	}
}

// entriesList: the entries as bullet lines.
func entriesList(list []Entry) []string {
	var out []string
	for _, e := range list {
		if e.Kind == KindApp {
			out = append(out, T("برنامه‌ی %s", ltr(e.Path)))
		} else if n := knownName(e.Kind, e.Port); n != "" {
			out = append(out, ltr(fmt.Sprintf("%s %d  (%s)", e.Kind, e.Port, n)))
		} else {
			out = append(out, ltr(fmt.Sprintf("%s %d", e.Kind, e.Port)))
		}
	}
	return out
}

// confirmTurnOn asks once, listing everything that will change.
func (a *App) confirmTurnOn(entries []Entry, codes []string) bool {
	st := a.last
	q := T("محافظت روشن شود؟") + nl + nl +
		T("کشورها:  %s", countriesText(codes)) + nl +
		T("پورت‌ها و برنامه‌ها:") + bulletList(entriesList(entries), 6, "") + nl + nl +
		T("بعد از این کار فقط IP های این کشورها به این پورت‌ها و برنامه‌ها وصل می‌شوند.") + " " + T(vpnNote) + nl
	var closing []string
	skipped := false
	for _, c := range st.Dangerous() {
		if c.CanClose && len(st.Sensitive(c.Covers)) == 0 {
			closing = append(closing, ltr(short(c.Display, 60)))
		} else {
			skipped = true
		}
	}
	q += nl + T("این کارها انجام می‌شود:") + nl +
		"•  " + T("برای این پورت‌ها و برنامه‌ها Rule های «فقط این کشورها» ساخته می‌شود.")
	if len(closing) > 0 {
		q += nl + "•  " + T("این Rule های قدیمی که برای همه باز بودند خاموش می‌شوند:") + bulletList(closing, 5, "      ")
	}
	q += nl + "•  " + T("لیست IP کشورها هر 4 هفته یک بار خودکار به‌روز می‌شود.")
	warn := false
	if st.FirewallProblem() {
		q += nl + "•  " + T("Windows Firewall روشن می‌شود (الان کار نمی‌کند).")
	}
	if st.InboundBlocked() {
		q += nl + "•  " + T("در Windows Firewall گزینه‌ی %s خاموش می‌شود (وگرنه Rule های محافظت اثر ندارند).", ltr("Block all incoming connections"))
	}
	if skipped {
		q += nl + nl + T("Rule هایی که پورت‌های دیگر یا Remote Desktop را هم باز می‌کنند خاموش نمی‌شوند؛ بعداً در بخش «مشکل‌ها» نشان داده می‌شوند.")
	}
	if w := a.wideningWarning(entries); w != "" {
		q += nl + nl + w
		warn = true
	}
	if st.FirewallProblem() || st.InboundBlocked() {
		if w := a.firewallWarning(entries); w != "" {
			q += nl + nl + w
			warn = true
		}
	}
	if s := st.Sensitive(entryKeys(entries)); len(s) > 0 {
		q += nl + nl + T("هشدار: %s برای %s است. اگر خودتان با VPN یا از کشور دیگری به این کامپیوتر وصل می‌شوید، دیگر نمی‌توانید وصل شوید.", keysText(s, entries), st.sensitiveNames(s))
		warn = true
	}
	q += nl + nl + T("با «%s» Rule های قدیمی به حالت قبل برمی‌گردند.", T(MainOff))
	return a.ui.Ask(q, warn)
}

// wideningWarning: entries that are closed now (or open only for a few IPs)
// become open for every IP of the chosen countries.
func (a *App) wideningWarning(entries []Entry) string {
	if a.last.FirewallProblem() {
		return ""
	}
	in := a.input(a.last)
	in.Entries = entries
	v := Assess(in)
	var closed, some []string
	for _, r := range v.Rows {
		switch r.State {
		case ClosedState:
			closed = append(closed, r.Key)
		case SomeIPsState:
			some = append(some, r.Key)
		}
	}
	w := ""
	if len(closed) > 0 {
		w += T("توجه: %s الان از بیرون بسته است و بعد از این کار برای همه‌ی IP های کشورهای انتخاب‌شده باز می‌شود.", keysText(closed, entries))
	}
	if len(some) > 0 {
		if w != "" {
			w += nl
		}
		w += T("توجه: %s الان فقط برای چند IP مشخص باز است و بعد از این کار برای همه‌ی IP های کشورهای انتخاب‌شده هم باز می‌شود.", keysText(some, entries))
	}
	return w
}

// firewallWarning: which listening services stop working from outside when
// the firewall is switched on ("" when none).
func (a *App) firewallWarning(entries []Entry) string {
	if a.last.InboundBlocked() && !a.last.FirewallProblem() {
		rules := a.last.OpenedByInbound(entries)
		if len(rules) == 0 {
			return ""
		}
		var items []string
		for _, r := range rules {
			items = append(items, ltr(r))
		}
		return T("هشدار: بعد از خاموش شدن گزینه‌ی %s، این Rule ها دوباره کار می‌کنند و برای همه باز می‌شوند:", ltr("Block all incoming connections")) + bulletList(items, 8, "") +
			nl + T("اگر یکی از این‌ها را نمی‌خواهید، %s را نزنید و اول آن Rule را در Windows Firewall خاموش کنید.", T(yesWord))
	}
	if !a.last.FirewallProblem() {
		return "" // only a profile not in use is off: nothing stops now
	}
	un := a.last.Uncovered(entries)
	if len(un) == 0 {
		return ""
	}
	var items []string
	rdp := false
	for _, p := range un {
		name := knownName(KindTCP, p)
		if n := a.last.ListenerName(KindTCP, p); n != "" && name == "" {
			name = n
		}
		if a.last.SensitiveName(fmt.Sprint(p)) == "Remote Desktop" {
			rdp = true
		}
		if name != "" {
			items = append(items, ltr(fmt.Sprintf("%d  %s", p, name)))
		} else {
			items = append(items, ltr(fmt.Sprint(p)))
		}
	}
	w := T("هشدار: بعد از روشن شدن Windows Firewall، این سرویس‌ها (TCP) از بیرون قطع می‌شوند، چون هیچ Rule بازشان نکرده:") + bulletList(items, 8, "")
	if rdp {
		w += nl + nl + T("Remote Desktop هم در این لیست است. اگر همین الان با Remote Desktop وصل هستید، اتصال شما قطع می‌شود. فقط وقتی %s را بزنید که به Console سرور دسترسی دارید.", T(yesWord))
	}
	return w
}

func bulletList(items []string, max int, indent string) string {
	s := ""
	for i, it := range items {
		if i == max {
			s += nl + indent + "•  " + T("و %d مورد دیگر", len(items)-max)
			break
		}
		s += nl + indent + "•  " + it
	}
	return s
}

func (a *App) TurnOn() {
	entries, codes := a.entries(), a.countries()
	if a.last.LocalRulesBlocked() {
		a.ui.Tell(T("Group Policy روی این کامپیوتر اجازه نمی‌دهد محافظت کار کند، پس روشن نشد.")+nl+nl+
			T("فقط مدیر دامنه (Domain Admin) می‌تواند این را درست کند."), LevelRed)
		return
	}
	if len(codes) == 0 {
		a.ui.Tell(T("اول دست‌کم یک کشور انتخاب کنید:")+nl+nl+
			T("1.  در بخش «کشورها»، کشور را از لیست انتخاب کنید.")+nl+
			T("2.  دکمه‌ی «افزودن کشور» را بزنید."), LevelOrange)
		return
	}
	if len(entries) == 0 {
		a.ui.Tell(T("اول دست‌کم یک پورت یا برنامه انتخاب کنید:")+nl+nl+
			T("1.  در بخش «پورت‌ها و برنامه‌ها»، پورت را بنویسید یا از لیست انتخاب کنید.")+nl+
			T("2.  دکمه‌ی «افزودن پورت» را بزنید."), LevelOrange)
		return
	}
	if !a.confirmTurnOn(entries, codes) {
		return
	}
	a.turnOn()
}

// turnOn does the work after the question was answered.
func (a *App) turnOn() {
	codes := a.countries()
	a.log("—— روشن کردن محافظت برای %s", countriesText(codes))
	fw := a.last.FirewallProblem() || a.last.InboundBlocked()
	lists, src, ok := a.list()
	if !ok {
		a.Refresh()
		a.ui.Tell(T("لیست IP کشورها از اینترنت دانلود نشد، پس محافظت روشن نشد و چیزی تغییر نکرد.")+nl+nl+
			T("در بخش «مشکل‌ها» دکمه‌ی «دریافت دستی لیست» را بزنید."), LevelOrange)
		return
	}
	if !a.protect(lists, src) {
		return
	}
	if fw && !a.enableFirewall() {
		return
	}
	st, ok := a.Refresh()
	if !ok {
		a.ui.Tell(T("Rule های محافظت نوشته شدند، ولی وضعیت Windows Firewall بعد از آن خوانده نشد. «%s» را بزنید.", T(MainCheck)), LevelOrange)
		return
	}
	if Assess(a.input(st)).Level == LevelRed {
		a.ui.Tell(T("محافظت روشن شد، ولی هنوز کامل کار نمی‌کند.")+nl+nl+T("مشکل‌ها در پایین پنجره نوشته شده‌اند."), LevelOrange)
		return
	}
	a.ui.Tell(T("محافظت روشن شد.")+nl+nl+T(vpnNote)+nl+nl+T("برای اطمینان، از یک کامپیوتر در یکی از کشورهای انتخاب‌شده و بدون VPN به سرویس وصل شوید."), LevelGreen)
}

// list: the lists of the chosen countries, downloaded now or picked by hand earlier.
func (a *App) list() (Lists, string, bool) {
	codes := a.countries()
	l, err := a.fetch(codes)
	if err == nil {
		return l, SourceDownload, true
	}
	if a.pending != nil && sameStrings(a.pendingCC, codes) {
		a.log("لیست دانلود نشد؛ لیستی که دستی انتخاب شده بود استفاده می‌شود")
		return *a.pending, SourceFile, true
	}
	return Lists{}, "", false
}

// protect writes our rules, closes safe old rules and switches on the
// monthly update. Returns false (and tells the user) when writing failed.
func (a *App) protect(l Lists, src string) bool {
	entries, codes := a.entries(), a.countries()
	t := a.last.Tags
	// a country whose list got much smaller (also one of several)
	var shrunk []string
	if len(a.last.Ours) > 0 {
		for _, cc := range codes {
			if was := t.Per[cc]; was > 0 && l.Per[cc]*100 < was*85 {
				shrunk = append(shrunk, T("%s: %.2f میلیون IP، قبلاً %.2f میلیون", CountryName(cc), float64(l.Per[cc])/1e6, float64(was)/1e6))
			}
		}
		if newAddr := addrTotal(l.Ranges); len(shrunk) == 0 && t.ListAddr > 0 && sameStrings(t.Countries, codes) && newAddr*100 < t.ListAddr*85 {
			shrunk = append(shrunk, T("همه: %.2f میلیون IP، قبلاً %.2f میلیون", float64(newAddr)/1e6, float64(t.ListAddr)/1e6))
		}
	}
	if len(shrunk) > 0 {
		if !a.ui.Ask(T("لیست تازه خیلی کوچک‌تر از لیست فعلی است. ممکن است ناقص باشد و بعضی کاربران دیگر وصل نشوند:")+bulletList(shrunk, 6, "")+nl+nl+
			T("با این حال از لیست تازه استفاده شود؟"), true) {
			a.log("لیست تازه خیلی کوچک‌تر از لیست فعلی بود؛ استفاده نشد")
			a.Refresh()
			return false
		}
	}
	a.log("لیست IP کشورها: %s، %d IP range (%s)", countriesText(codes), len(l.Ranges), src)
	a.step("نوشتن Rule های محافظت در Windows Firewall…")
	if err := a.core.ApplyRules(l, entries, codes, src); err != nil {
		a.log("نوشتن Rule ها در Windows Firewall انجام نشد: %v", err)
		a.Refresh()
		a.ui.Tell(T("نوشتن تنظیمات در Windows Firewall انجام نشد.")+" "+T(support), LevelRed)
		return false
	}
	a.log("Rule های محافظت نوشته شدند")
	if src == SourceFile {
		a.pending, a.pendingCC = nil, nil
	}
	a.fetchFailed = false
	a.afterRules()
	return true
}

// afterRules: close the safe old rules and make sure the monthly update runs.
func (a *App) afterRules() {
	if len(a.last.Old) > 0 {
		a.migrateTried = false // the new rules are whole now: the old ones can go
	}
	st, ok := a.Refresh()
	if !ok {
		return
	}
	a.closeSafeRules(st)
	if !st.TaskCurrent() {
		a.setAuto(false)
	}
	a.Refresh()
}

// closeSafeRules switches off old rules that open only our entries to the
// whole world. Never rules that also open other ports or remote-management
// ports: those are shown as problems with a careful button.
func (a *App) closeSafeRules(st Status) int {
	var list []Conflict
	for _, c := range st.Dangerous() {
		if c.CanClose && len(st.Sensitive(c.Covers)) == 0 {
			list = append(list, c)
		}
	}
	return a.switchOff(list, T("Rule قدیمی"))
}

// switchOff turns rules off and remembers them so "turn off" restores them.
// Returns how many failed.
func (a *App) switchOff(list []Conflict, what string) int {
	if len(list) == 0 {
		return 0
	}
	a.step("خاموش کردن Rule های قدیمی…")
	var names []string
	var plan []OffRule
	byName := map[string]Conflict{}
	for _, c := range list {
		names = append(names, c.Name)
		plan = append(plan, OffRule{Name: c.Name, Covers: c.Covers})
		byName[c.Name] = c
	}
	// remember first: a rule switched off without a record could never come back
	before := append([]OffRule(nil), a.last.Tags.Off...)
	if !a.saveOff(mergeOff(append([]OffRule(nil), before...), plan)) {
		return len(list)
	}
	done, gone, failed, err := a.core.SetRules(names, false)
	if err != nil {
		// some rules may have been switched off before the error (for example a
		// timeout): keep all of them recorded; switching an enabled rule on again later is harmless
		a.log("خاموش کردن %s انجام نشد: %v", what, err)
		return len(list)
	}
	var closed []OffRule
	for _, n := range done {
		a.log("%s خاموش شد: %s", what, byName[n].Display)
		closed = append(closed, OffRule{Name: n, Covers: byName[n].Covers})
	}
	for _, n := range gone {
		a.log("%s دیگر وجود ندارد: %s", what, byName[n].Display)
	}
	for n, msg := range failed {
		a.log("%s خاموش نشد: %s (%s)", what, byName[n].Display, msg)
	}
	if len(closed) != len(list) {
		a.saveOff(mergeOff(before, closed))
	}
	return len(failed)
}

// saveOff stores the list of rules this program switched off.
func (a *App) saveOff(list []OffRule) bool {
	if err := a.core.SetTags(map[string]string{"OFF": encodeOff(list)}); err != nil {
		a.log("ذخیره‌ی لیست Rule های بسته‌شده انجام نشد: %v", err)
		return false
	}
	a.last.Tags.Off = list
	return true
}

// restore switches rules this program had turned off back on. ok=false:
// Windows could not be asked at all (nothing changed).
func (a *App) restore(list []OffRule) (ok bool, failed []string) {
	if len(list) == 0 {
		return true, nil
	}
	a.step("روشن کردن دوباره‌ی Rule های قدیمی…")
	done, gone, fails, err := a.core.SetRules(offNames(list), true)
	if err != nil {
		a.log("روشن کردن Rule های قدیمی انجام نشد: %v", err)
		return false, offNames(list)
	}
	for _, n := range done {
		a.log("Rule قدیمی دوباره روشن شد: %s", a.display(n))
	}
	for _, n := range gone {
		a.log("Rule «%s» دیگر وجود ندارد؛ از لیست برداشته شد", n)
	}
	for n, msg := range fails {
		a.log("Rule قدیمی روشن نشد: %s (%s)", a.display(n), msg)
		failed = append(failed, n)
	}
	sort.Strings(failed)
	return true, failed
}

// display: the readable name of a rule, when known.
func (a *App) display(name string) string {
	for _, c := range append(append([]Conflict(nil), a.last.Conflicts...), a.last.Blocks...) {
		if c.Name == name && c.Display != "" {
			return c.Display
		}
	}
	return name
}

// ---------------------------------------------------------------- turning off

func (a *App) TurnOff() {
	off := a.last.Tags.Off
	entries := a.entries()
	q := T("محافظت خاموش شود؟") + nl + nl + T("Rule های «فقط این کشورها» حذف می‌شوند و به‌روزرسانی خودکار خاموش می‌شود.")
	if len(off) > 0 {
		var names []string
		for _, r := range off {
			names = append(names, ltr(short(a.display(r.Name), 60)))
		}
		q += nl + nl + T("این Rule های قدیمی دوباره روشن می‌شوند (به حالت قبل)، یعنی دوباره برای همه باز می‌شوند:") + bulletList(names, 6, "")
	}
	// what each entry will be afterwards
	var shut []string
	if !a.last.FirewallProblem() {
		for _, e := range entries {
			k := e.Key()
			open := false
			for _, r := range off {
				open = open || containsStr(r.Covers, k)
			}
			for _, c := range a.last.Conflicts {
				open = open || (c.Enabled && containsStr(c.Covers, k))
			}
			if !open {
				shut = append(shut, k)
			}
		}
	}
	if len(shut) > 0 {
		q += nl + nl + T("هشدار: بعد از این کار، %s برای همه، حتی کشورهای انتخاب‌شده، بسته می‌شود؛ چون Rule دیگری آن را باز نمی‌کند. یعنی کاربران دیگر نمی‌توانند وصل شوند.", keysText(shut, entries))
	}
	if a.last.Tags.FwOn {
		q += nl + nl + T("Windows Firewall که این برنامه روشن کرده بود، برای امنیت روشن می‌ماند.")
	}
	if !a.ui.Ask(q, true) {
		return
	}
	a.log("—— خاموش کردن محافظت")
	ok, failed := a.restore(off)
	if !ok || len(failed) > 0 {
		// keep the rules (and the list stored in them) until the old rules are back
		a.Refresh()
		msg := T("خاموش کردن محافظت انجام نشد و چیزی تغییر نکرد.") + " " + T(support)
		if ok {
			var names []string
			for _, n := range failed {
				names = append(names, ltr(a.display(n)))
			}
			msg = T("این Rule های قدیمی دوباره روشن نشدند، پس محافظت روشن ماند تا چیزی از دست نرود:") + bulletList(names, 6, "") + nl + nl + T(support)
		}
		a.ui.Tell(msg, LevelRed)
		return
	}
	var problems []string
	a.step("خاموش کردن به‌روزرسانی خودکار…")
	if err := a.core.Schedule(false); err != nil {
		a.log("خاموش کردن به‌روزرسانی خودکار انجام نشد: %v", err)
		problems = append(problems, T("خاموش کردن به‌روزرسانی خودکار"))
	}
	a.step("حذف Rule های محافظت…")
	if err := a.core.RemoveRules(); err != nil {
		a.log("حذف Rule های محافظت انجام نشد: %v", err)
		problems = append(problems, T("حذف Rule های محافظت"))
	} else {
		a.log("Rule های محافظت حذف شدند")
	}
	a.Refresh()
	if len(problems) > 0 {
		a.ui.Tell(T("خاموش کردن محافظت کامل انجام نشد:")+bulletList(problems, 5, "")+nl+nl+T("دوباره «%s» را بزنید.", T(MainOff)), LevelRed)
		return
	}
	done := T("محافظت خاموش شد.")
	if len(off) > 0 {
		done += " " + T("Rule های قدیمی به حالت قبل برگشتند.")
	}
	if len(shut) > 0 {
		done += nl + nl + T("%s الان برای همه بسته است.", keysText(shut, entries))
	}
	a.ui.Tell(done, LevelGreen)
}

// ---------------------------------------------------------------- fixing problems

// Fix handles the button next to one problem.
func (a *App) Fix(p Problem) {
	switch p.Kind {
	case FixFirewall:
		q := T("Windows Firewall روشن شود؟") + nl + nl + T("بعد از روشن شدن، هر اتصال Inbound که Rule نداشته باشد بسته می‌شود.")
		warn := a.firewallWarning(a.entries())
		if warn != "" {
			q += nl + nl + warn
		}
		if !a.ui.Ask(q, true) {
			return
		}
		a.enableFirewall()
		a.Refresh()
	case FixReapply:
		a.log("—— نوشتن دوباره‌ی Rule های محافظت")
		a.reapply()
	case FixUpdateList:
		a.log("—— به‌روزرسانی لیست IP کشورها")
		if a.updateList() {
			a.ui.Tell(T("لیست IP کشورها به‌روز شد."), LevelGreen)
		}
	case FixCloseRule, FixCloseBroad:
		a.closeOne(p.Rule, p.Kind == FixCloseBroad || len(a.last.Sensitive(p.Rule.Covers)) > 0)
	case FixBlockRule:
		if !a.ui.Ask(T("این Rule از نوع Block خاموش شود؟")+nl+nl+ltr(p.Rule.Display)+nl+nl+
			T("بعد از آن، %s فقط برای IP های کشورهای انتخاب‌شده باز می‌شود. با «%s» دوباره روشن می‌شود.", keysText(p.Rule.Covers, a.entries()), T(MainOff)), false) {
			return
		}
		if a.switchOff([]Conflict{p.Rule}, T("Rule از نوع Block")) > 0 {
			a.Refresh()
			a.ui.Tell(T("خاموش کردن این Rule انجام نشد.")+" "+T(support), LevelRed)
			return
		}
		a.Refresh()
	case FixManualList:
		a.manualList()
	case FixAutoUpdate:
		if a.setAuto(true) {
			a.Refresh()
		}
	case FixMigrate:
		a.migrateTried = false
		if st, ok := a.Refresh(); ok && len(st.Old) > 0 && len(st.Ours) > 0 && !st.RulesMatch(a.entries()) {
			a.reapply() // the old rules go once ours are whole
		}
	}
}

// FixAll fixes every problem that does not need a separate decision, after
// one confirmation that lists the steps.
func (a *App) FixAll() {
	var steps []Problem
	seen := map[FixKind]bool{}
	for _, p := range a.view.Problems {
		if !autoFixable(p.Kind) {
			continue
		}
		if p.Kind != FixCloseRule && p.Kind != FixBlockRule {
			if seen[p.Kind] {
				continue
			}
			seen[p.Kind] = true
		}
		steps = append(steps, p)
	}
	if len(steps) == 0 {
		a.Refresh()
		return
	}
	q := T("این کارها انجام شود؟") + nl
	warn := false
	for _, p := range steps {
		q += nl + "•  " + p.Step
	}
	if seen[FixFirewall] {
		if w := a.firewallWarning(a.entries()); w != "" {
			q += nl + nl + w
			warn = true
		}
	}
	if !a.ui.Ask(q, warn) {
		return
	}
	a.log("—— درست کردن مشکل‌ها")
	if seen[FixMigrate] {
		a.migrateTried = false
		if _, ok := a.Refresh(); !ok {
			return
		}
	}
	// our rules first: if they cannot be written, nothing else is touched
	downloads := seen[FixReapply] && !a.last.Repairable() // reapply will download the list itself
	if seen[FixReapply] && !a.reapply() {
		return
	}
	if seen[FixUpdateList] && !downloads && !a.updateList() {
		return
	}
	failed := 0
	var closeList, blockList []Conflict
	for _, p := range steps {
		switch p.Kind {
		case FixCloseRule:
			closeList = append(closeList, p.Rule)
		case FixBlockRule:
			blockList = append(blockList, p.Rule)
		}
	}
	failed += a.switchOff(closeList, T("Rule قدیمی"))
	failed += a.switchOff(blockList, T("Rule از نوع Block"))
	if seen[FixFirewall] && !a.enableFirewall() {
		failed++
	}
	if seen[FixAutoUpdate] && !a.setAuto(false) {
		failed++
	}
	st, ok := a.Refresh()
	if !ok {
		return
	}
	v := Assess(a.input(st))
	switch {
	case failed > 0:
		a.ui.Tell(T("بعضی کارها انجام نشد.")+" "+T(support), LevelRed)
	case len(v.Problems) > 0:
		a.ui.Tell(T("کارها انجام شد. موردهایی که تصمیمش با شماست هنوز در بخش «مشکل‌ها» هستند."), LevelOrange)
	default:
		a.ui.Tell(T("همه‌ی مشکل‌ها درست شد."), LevelGreen)
	}
}

// reapply writes the settings of our rules again: with the IP ranges they
// hold when those are intact, otherwise with a fresh list.
func (a *App) reapply() bool {
	if !a.last.Repairable() {
		return a.updateList()
	}
	a.step("نوشتن دوباره‌ی Rule های محافظت…")
	if err := a.core.RepairRules(a.last.SourceRanges(), a.entries()); err != nil {
		a.log("نوشتن دوباره‌ی Rule ها انجام نشد: %v", err)
		a.Refresh()
		a.ui.Tell(T("نوشتن دوباره‌ی Rule ها انجام نشد.")+" "+T(support), LevelRed)
		return false
	}
	a.log("Rule های محافظت دوباره نوشته شدند")
	a.afterRules()
	return true
}

// updateList downloads the lists now and rewrites the rules.
func (a *App) updateList() bool {
	lists, src, ok := a.list()
	if !ok {
		a.Refresh()
		a.ui.Tell(T("لیست IP کشورها دانلود نشد و چیزی تغییر نکرد. در بخش «مشکل‌ها» دکمه‌ی «دریافت دستی لیست» را بزنید."), LevelOrange)
		return false
	}
	return a.protect(lists, src)
}

func (a *App) enableFirewall() bool {
	a.step("روشن کردن Windows Firewall…")
	if err := a.core.EnableFirewall(); err != nil {
		a.log("روشن کردن Windows Firewall انجام نشد: %v", err)
		a.Refresh()
		a.ui.Tell(T("Windows Firewall روشن نشد. احتمالاً Group Policy آن را خاموش نگه داشته؛ در این صورت فقط مدیر دامنه می‌تواند تغییرش دهد."), LevelRed)
		return false
	}
	// Group Policy can keep it off although the command worked
	if st, err := a.core.Status(a.entries()); err == nil && !st.FirewallProblem() && st.InboundBlocked() {
		a.log("گزینه‌ی Block all incoming connections بعد از خاموش کردن هنوز روشن است (احتمالاً Group Policy)")
		a.Refresh()
		a.ui.Tell(T("گزینه‌ی %s خاموش نماند. احتمالاً Group Policy آن را روشن نگه می‌دارد؛ در این صورت فقط مدیر دامنه (Domain Admin) می‌تواند تغییرش دهد.", ltr("Block all incoming connections")), LevelRed)
		return false
	} else if err == nil && st.FirewallProblem() {
		a.log("Windows Firewall بعد از روشن کردن هنوز خاموش است (احتمالاً Group Policy)")
		a.Refresh()
		a.ui.Tell(T("Windows Firewall روشن نماند. احتمالاً Group Policy آن را خاموش نگه می‌دارد؛ در این صورت فقط مدیر دامنه (Domain Admin) می‌تواند تغییرش دهد."), LevelRed)
		return false
	} else if err != nil {
		a.log("Windows Firewall روشن شد، ولی وضعیت بعد از آن خوانده نشد: %v", err)
		return true
	}
	a.log("Windows Firewall روشن شد")
	return true
}

func (a *App) closeOne(c Conflict, careful bool) {
	q := T("این Rule خاموش شود؟") + nl + nl + ltr(c.Display) + nl + nl + T("بعد از آن، %s فقط برای IP های کشورهای انتخاب‌شده باز است. با «%s» این Rule دوباره روشن می‌شود.", keysText(c.Covers, a.entries()), T(MainOff))
	if careful {
		q = T("هشدار: این Rule ممکن است برای وصل شدن خود شما یا سرویس‌های دیگر لازم باشد (مثلاً Remote Desktop):") + nl + nl + ltr(c.Display) + nl + nl +
			T("اگر آن را ببندید، ممکن است دیگر نتوانید از بیرون به این کامپیوتر وصل شوید.") + nl +
			T("فقط وقتی %s را بزنید که مطمئن هستید یا به Console سرور دسترسی دارید.", T(yesWord))
	}
	if !a.ui.Ask(q, true) {
		return
	}
	if a.switchOff([]Conflict{c}, T("Rule قدیمی")) > 0 {
		a.Refresh()
		a.ui.Tell(T("خاموش کردن این Rule انجام نشد.")+" "+T(support), LevelRed)
		return
	}
	a.Refresh()
}

// manualList: for each chosen country, open its page, let the user save it
// and pick the file; then protect with all of them.
func (a *App) manualList() {
	codes := a.countries()
	if len(codes) == 0 {
		a.ui.Tell(T("اول دست‌کم یک کشور انتخاب کنید."), LevelOrange)
		return
	}
	per := map[string][]string{}
	for i, cc := range codes {
		url := RipeURL(cc)
		head := T("کشور %d از %d:  %s", i+1, len(codes), countryLabel(cc)) + nl + nl
		how := head + T("صفحه‌ی لیست این کشور در مرورگر باز شد. اگر روی این سرور باز نشد (مثلاً مرورگر اجازه نداد)، همین کار را روی یک کامپیوتر دیگر انجام دهید و فایل را به اینجا کپی کنید.") + nl + nl +
			T("1.  صفحه را با کلیدهای Ctrl و S ذخیره کنید.") + nl +
			T("2.  بعد اینجا «OK (تأیید)» را بزنید و همان فایل را انتخاب کنید.") + nl + nl +
			T("آدرس صفحه:") + nl + url
		if !a.ui.OpenURL(url) {
			how = head + T("مرورگر روی این سرور باز نشد.") + nl + nl +
				T("1.  روی یک کامپیوتر دیگر این آدرس را در مرورگر باز کنید و صفحه را با Ctrl و S ذخیره کنید:") + nl + url + nl +
				T("2.  فایل را روی این سرور کپی کنید.") + nl +
				T("3.  بعد اینجا «OK (تأیید)» را بزنید و همان فایل را انتخاب کنید.")
		}
		a.ui.Tell(how, LevelGrey)
		path := a.ui.PickFile(false)
		if path == "" {
			a.Refresh()
			return
		}
		b, err := readFileLimited(path, 64<<20)
		if err != nil {
			a.ui.Tell(T("فایل خوانده نشد:")+" "+err.Error(), LevelRed)
			return
		}
		r, err := ParseRanges(b)
		if err != nil {
			a.log("فایل لیست قابل استفاده نیست: %v", err)
			a.ui.Tell(T("این فایل، لیست IP کشور %s نیست یا ناقص ذخیره شده. دوباره امتحان کنید.", CountryName(cc)), LevelRed)
			return
		}
		a.log("لیست IP %s از فایل خوانده شد (%d IP range)", CountryName(cc), len(r))
		per[cc] = r
	}
	all, err := combine(per)
	if err != nil {
		a.ui.Tell(err.Error(), LevelRed)
		return
	}
	a.pending, a.pendingCC = &all, codes
	a.fetchFailed = false
	if a.isOn() {
		if a.protect(all, SourceFile) {
			a.ui.Tell(T("لیست IP کشورها به‌روز شد."), LevelGreen)
		}
		return
	}
	a.Refresh()
	entries := a.entries()
	if a.last.LocalRulesBlocked() || len(entries) == 0 || !a.confirmTurnOn(entries, codes) {
		return
	}
	a.turnOn()
}

// setAuto switches on the monthly update. tell: show errors in a box.
func (a *App) setAuto(tell bool) bool {
	a.step("روشن کردن به‌روزرسانی خودکار…")
	if err := a.core.Schedule(true); err != nil {
		a.log("روشن کردن به‌روزرسانی خودکار انجام نشد: %v", err)
		if tell {
			a.ui.Tell(T("به‌روزرسانی خودکار روشن نشد.")+" "+T(support), LevelRed)
		}
		return false
	}
	a.log("به‌روزرسانی خودکار روشن شد (هر 4 هفته یک بار)")
	return true
}

func (a *App) fetch(codes []string) (Lists, error) {
	a.step("دانلود لیست IP کشورها…")
	l, err := a.core.FetchRanges(context.Background(), codes)
	if err != nil {
		a.log("لیست IP کشورها دانلود نشد: %v", err)
		a.fetchFailed = true
		return Lists{}, err
	}
	a.fetchFailed = false
	return l, nil
}

// ---------------------------------------------------------------- ports and programs

// AddPort accepts "808", "UDP 1194" or a line of the list like
// "TCP 3389   Remote Desktop". proto is used when the text has none.
func (a *App) AddPort(text, proto string) bool {
	text = strings.TrimSpace(toLatinDigits(text))
	f := strings.Fields(text)
	if len(f) >= 2 && (strings.EqualFold(f[0], "TCP") || strings.EqualFold(f[0], "UDP")) {
		text = f[0] + " " + f[1]
	} else if len(f) > 0 {
		text = proto + " " + f[0]
	}
	e, ok := ParseEntry(text)
	if !ok || e.Kind == KindApp {
		a.ui.Tell(T("شماره‌ی پورت درست نیست. یک عدد بین 1 تا 65535 بنویسید."), LevelOrange)
		return false
	}
	return a.addEntry(e)
}

// AddProgram adds a program (its .exe file).
func (a *App) AddProgram(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	low := strings.ToLower(baseName(path))
	if !strings.HasSuffix(low, ".exe") {
		a.ui.Tell(T("فقط فایل برنامه (exe) را می‌شود اضافه کرد."), LevelOrange)
		return false
	}
	if strings.HasPrefix(path, `\\?\`) && len(path) > 6 && path[5] == ':' {
		path = path[4:] // \\?\C:\app.exe is the same as C:\app.exe
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") || remotePath(path) {
		a.ui.Tell(T("برنامه‌ای که روی یک پوشه‌ی شبکه (Network Share) است اضافه نمی‌شود، چون هر کسی که به آن پوشه دسترسی دارد می‌تواند فایل را عوض کند. برنامه را روی خود این سرور نصب کنید."), LevelOrange)
		return false
	}
	if sharedHosts[low] {
		a.ui.Tell(T("%s برنامه‌ی مشترک خود Windows است و خیلی از سرویس‌ها یا Script ها با آن کار می‌کنند. به جای آن، پورت سرویس را اضافه کنید.", ltr(baseName(path))), LevelOrange)
		return false
	}
	if self, err := os.Executable(); err == nil && samePath(self, path) {
		return false
	}
	if _, err := os.Stat(path); err != nil {
		a.ui.Tell(T("این فایل پیدا نشد:")+nl+ltr(path), LevelOrange)
		return false
	}
	if !protectedFolder(path) && !a.ui.Ask(T("هشدار: این برنامه در پوشه‌ای است که شاید کاربران دیگر هم بتوانند فایل‌هایش را عوض کنند:")+nl+ltr(path)+nl+nl+
		T("اگر کسی این فایل را با برنامه‌ی دیگری عوض کند، آن برنامه هم از کشورهای انتخاب‌شده روی همه‌ی پورت‌ها قابل دسترس می‌شود. برنامه‌های سرور بهتر است در %s نصب شوند.", ltr(`C:\Program Files`))+nl+nl+T("ادامه می‌دهید؟"), true) {
		return false
	}
	return a.addEntry(AppEntry(path))
}

// sharedHosts: programs of Windows that run other people's services or
// scripts; opening them would open far more than one program.
var sharedHosts = map[string]bool{
	"svchost.exe": true, "system": true, "lsass.exe": true, "services.exe": true, "powershell.exe": true, "pwsh.exe": true,
	"cmd.exe": true, "rundll32.exe": true, "dllhost.exe": true, "mshta.exe": true, "wscript.exe": true, "cscript.exe": true,
	"regsvr32.exe": true, "conhost.exe": true, "explorer.exe": true, "python.exe": true, "pythonw.exe": true,
	"node.exe": true, "java.exe": true, "javaw.exe": true, "w3wp.exe": true, "msiexec.exe": true,
}

// protectedFolder: inside Program Files or Windows, where only
// Administrators can change files.
func protectedFolder(path string) bool {
	p := strings.ToLower(normPath(path))
	if strings.Contains(p, `\temp\`) || strings.Contains(p, `\tmp\`) {
		return false // anyone can write there
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SystemRoot"} {
		if d := os.Getenv(env); d != "" && strings.HasPrefix(p, strings.ToLower(strings.TrimRight(d, `\`))+`\`) {
			return true
		}
	}
	for _, d := range []string{`c:\program files\`, `c:\program files (x86)\`, `c:\windows\`} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

func (a *App) addEntry(e Entry) bool {
	entries := a.entries()
	if hasEntry(entries, e.Key()) {
		a.ui.Tell(T("%s از قبل در لیست هست.", keyText(e.Key(), []Entry{e})), LevelOrange)
		return false
	}
	name := a.last.SensitiveName(e.Key())
	switch {
	case name != "":
		if !a.ui.Ask(T("هشدار: %s برای %s است.", keyText(e.Key(), []Entry{e}), name)+nl+nl+
			T("اگر خودتان با VPN یا از کشور دیگری به این کامپیوتر وصل می‌شوید، وقتی محافظت روشن باشد دیگر نمی‌توانید وصل شوید.")+nl+nl+T("ادامه می‌دهید؟"), true) {
			return false
		}
	case a.isOn():
		q := T("%s اضافه شود؟", keyText(e.Key(), []Entry{e})) + nl + nl + T("محافظت روشن است، پس همین حالا برای IP های کشورهای انتخاب‌شده باز می‌شود.")
		if e.Kind == KindApp {
			q += nl + nl + T("این برنامه روی هر پورتی که کار کند، برای این کشورها باز است.")
		}
		if w := a.wideningWarning([]Entry{e}); w != "" {
			q += nl + nl + w
		}
		if !a.ui.Ask(q, false) {
			return false
		}
	}
	if err := a.core.SaveEntries(append(entries, e)); err != nil {
		a.ui.Tell(T("لیست پورت‌ها ذخیره نشد:")+" "+err.Error(), LevelRed)
		return false
	}
	a.log("%s به لیست اضافه شد", keyText(e.Key(), []Entry{e}))
	return a.afterEntryChange(nil, entries)
}

// RemoveEntry removes a port or program by its key.
func (a *App) RemoveEntry(key string) {
	entries := a.entries()
	var left []Entry
	var gone Entry
	for _, x := range entries {
		if x.Key() != key {
			left = append(left, x)
		} else {
			gone = x
		}
	}
	if len(left) == len(entries) {
		return
	}
	what := keyText(key, entries)
	if len(left) == 0 && a.isOn() {
		a.ui.Tell(T("این تنها مورد لیست است و حذف نمی‌شود. اگر محافظت را نمی‌خواهید، «%s» را بزنید.", T(MainOff)), LevelOrange)
		return
	}
	// old rules this program closed come back once none of what they
	// opened is in the list any more
	var back []OffRule
	if a.isOn() {
		for _, r := range a.last.Tags.Off {
			if !containsStr(r.Covers, key) {
				continue
			}
			still := false
			for _, k := range r.Covers {
				still = still || hasEntry(left, k)
			}
			if !still {
				back = append(back, r)
			}
		}
	}
	q := T("%s از لیست حذف شود؟", what)
	if a.isOn() {
		q += nl + nl + T("محافظت دیگر آن را شامل نمی‌شود.")
		if len(back) > 0 {
			var names []string
			for _, r := range back {
				names = append(names, ltr(short(a.display(r.Name), 50)))
			}
			q += " " + T("این Rule های قدیمی دوباره روشن می‌شوند (به حالت قبل):") + bulletList(names, 5, "")
		} else if gone.Kind == KindApp {
			q += " " + T("برنامه از بیرون (حتی از کشورهای انتخاب‌شده) بسته می‌شود، مگر Rule دیگری آن را باز کند.")
		} else {
			q += " " + T("پورت از بیرون (حتی از کشورهای انتخاب‌شده) بسته می‌شود، مگر Rule دیگری آن را باز کند.")
		}
	}
	if !a.ui.Ask(q, false) {
		return
	}
	if err := a.core.SaveEntries(left); err != nil {
		a.ui.Tell(T("لیست پورت‌ها ذخیره نشد:")+" "+err.Error(), LevelRed)
		return
	}
	a.log("%s از لیست حذف شد", what)
	if a.afterEntryChange(back, entries) && gone.Kind == KindApp && a.isOn() {
		a.forgetProgram(gone.Path, left)
	}
}

// afterEntryChange: when protection is on, the rules follow the list at
// once. If they cannot, the list goes back to how it was, so it never
// disagrees with the rules. old: the list before the change.
func (a *App) afterEntryChange(back []OffRule, old []Entry) bool {
	if !a.isOn() {
		a.Refresh()
		return true
	}
	if !a.reapply() {
		if err := a.core.SaveEntries(old); err != nil {
			a.log("برگرداندن لیست پورت‌ها انجام نشد: %v", err)
		}
		a.log("لیست پورت‌ها به حالت قبل برگشت، چون Rule ها نوشته نشدند")
		a.Refresh()
		a.ui.Tell(T("لیست پورت‌ها و برنامه‌ها مثل قبل ماند، چون Rule ها کامل نوشته نشدند. اگر در بخش «مشکل‌ها» چیزی آمد، دکمه‌ی آن را بزنید."), LevelOrange)
		return false
	}
	if len(back) > 0 {
		ok, failed := a.restore(back)
		if ok {
			var keep []OffRule
			for _, r := range a.last.Tags.Off {
				if !containsStr(offNames(back), r.Name) || containsStr(failed, r.Name) {
					keep = append(keep, r)
				}
			}
			a.saveOff(keep)
		}
		if !ok || len(failed) > 0 {
			a.ui.Tell(T("یک Rule قدیمی دوباره روشن نشد.")+" "+T(support), LevelOrange)
		}
		a.Refresh()
	}
	return true
}

// ---------------------------------------------------------------- countries

func (a *App) AddCountry(code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	if _, ok := countryByCode(code); !ok {
		a.ui.Tell(T("اول یک کشور را از لیست انتخاب کنید."), LevelOrange)
		return false
	}
	codes := a.countries()
	if containsStr(codes, code) {
		a.ui.Tell(T("%s از قبل در لیست هست.", CountryName(code)), LevelOrange)
		return false
	}
	if a.isOn() && !a.ui.Ask(T("کشور %s اضافه شود؟", CountryName(code))+nl+nl+
		T("محافظت روشن است، پس لیست IP این کشور همین حالا دانلود می‌شود و کاربران آن هم می‌توانند وصل شوند."), false) {
		return false
	}
	if err := a.core.SaveCountries(append(codes, code)); err != nil {
		a.ui.Tell(T("لیست کشورها ذخیره نشد:")+" "+err.Error(), LevelRed)
		return false
	}
	a.log("کشور %s به لیست اضافه شد", CountryName(code))
	return a.afterCountryChange(codes)
}

func (a *App) RemoveCountry(code string) {
	codes := a.countries()
	if !containsStr(codes, code) {
		return
	}
	var left []string
	for _, c := range codes {
		if c != code {
			left = append(left, c)
		}
	}
	if len(left) == 0 && a.isOn() {
		a.ui.Tell(T("این تنها کشور لیست است و حذف نمی‌شود. اگر محافظت را نمی‌خواهید، «%s» را بزنید.", T(MainOff)), LevelOrange)
		return
	}
	q := T("کشور %s از لیست حذف شود؟", CountryName(code))
	if a.isOn() {
		q += nl + nl + T("محافظت روشن است، پس لیست IP بقیه‌ی کشورها همین حالا دوباره دانلود می‌شود و کاربران %s دیگر نمی‌توانند وصل شوند.", CountryName(code))
	}
	if !a.ui.Ask(q, a.isOn()) {
		return
	}
	if err := a.core.SaveCountries(left); err != nil {
		a.ui.Tell(T("لیست کشورها ذخیره نشد:")+" "+err.Error(), LevelRed)
		return
	}
	a.log("کشور %s از لیست حذف شد", CountryName(code))
	a.afterCountryChange(codes)
}

// afterCountryChange: when protection is on, the lists of the new set of
// countries are downloaded and written at once; if that fails, the list of
// countries goes back to how it was.
func (a *App) afterCountryChange(old []string) bool {
	if !a.isOn() {
		a.Refresh()
		return true
	}
	if !a.updateList() {
		if err := a.core.SaveCountries(old); err != nil {
			a.log("برگرداندن لیست کشورها انجام نشد: %v", err)
		}
		a.log("لیست کشورها به حالت قبل برگشت، چون لیست IP دانلود یا نوشته نشد")
		a.Refresh()
		return false
	}
	a.ui.Tell(T("Rule های محافظت برای این کشورها نوشته شدند: %s", countriesText(a.countries())), LevelGreen)
	return true
}

var toLatin = strings.NewReplacer("۰", "0", "۱", "1", "۲", "2", "۳", "3", "۴", "4", "۵", "5", "۶", "6", "۷", "7", "۸", "8", "۹", "9",
	"٠", "0", "١", "1", "٢", "2", "٣", "3", "٤", "4", "٥", "5", "٦", "6", "٧", "7", "٨", "8", "٩", "9")

func toLatinDigits(s string) string { return toLatin.Replace(s) }

func readFileLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}
