package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// go test -run TestDumpViews with DUMP=path writes sample screens for the mock-up renderer.
func TestDumpViews(t *testing.T) {
	out := os.Getenv("DUMP")
	if out == "" {
		t.Skip()
	}
	if v := os.Getenv("DUMPVER"); v != "" {
		old := Version
		Version = v
		defer func() { Version = old }()
	}
	type screen struct {
		View      View
		Layout    Layout
		RTL       bool
		Text      map[string]string
		States    []string
		Countries []string
		Combo     string
	}
	views := map[string]screen{}
	exe := filepath.Join(t.TempDir(), "RevitServer.exe")
	os.WriteFile(exe, nil, 0o644)
	shot := func(name string, fw *fakeFW, codes []string, entries []Entry, prep func(a *App, ui *fakeUI, c *Core)) {
		c := newCore(t, fw)
		c.SaveCountries(codes)
		c.SaveEntries(entries)
		a, ui, _ := startApp(t, c, lists)
		ui.answer = true
		if prep != nil {
			prep(a, ui, c)
		}
		a.Refresh()
		sc := screen{View: ui.view, Layout: computeLayout(ui.view, true, false, false, approxMeasure, 900), RTL: lang == "fa"}
		sc.View.Main = T(ui.view.Main)
		for _, r := range ui.view.Rows {
			sc.States = append(sc.States, T(r.State))
		}
		for _, c := range ui.view.Countries {
			sc.Countries = append(sc.Countries, countryLabelPlain(c))
		}
		sc.Combo = countryLabelPlain("AE")
		langName := "English"
		if lang == "en" {
			langName = "فارسی"
		}
		sc.Text = map[string]string{
			"off": T(MainOff), "check": T(MainCheck), "details": T("جزئیات فنی"), "copy": T("کپی متن"),
			"countries": T("کشورها (فقط این کشورها می‌توانند وصل شوند)"), "addCountry": T("افزودن کشور"), "remCountry": T("حذف کشور انتخاب‌شده"),
			"ports": T("پورت‌ها و برنامه‌ها"), "item": T("مورد"), "service": T("سرویس"), "state": T("وضعیت"),
			"addLabel": T("افزودن پورت:"), "cue": T("مثلاً 808"), "add": T("افزودن پورت"), "addApp": T("افزودن برنامه (exe)…"), "remove": T("حذف مورد انتخاب‌شده"),
			"problems": T("مشکل‌ها"), "problemsN": T("مشکل‌ها (%d)", len(ui.view.Problems)), "noProb": T("✔  مشکلی نیست."), "lang": langName, "copyProb": T("کپی متن مشکل‌ها"),
			"title": appTitle(),
		}
		prefix := ""
		if lang == "en" {
			prefix = "en-"
		}
		views[prefix+name] = sc
	}
	ir := []string{"IR"}
	for _, l := range []string{"fa", "en"} {
		lang = l
		shot("0-new", &fakeFW{}, nil, nil, nil)
		shot("1-off", &fakeFW{others: []*fakeRule{{name: "wcf", display: "Net.TCP Listener Adapter", source: "Local", open: true, enabled: true}}}, ir, []Entry{TCP(808)}, nil)
		shot("2-on", &fakeFW{}, []string{"DE", "IR", "AE"}, []Entry{TCP(808), TCP(3389), UDP(1194), AppEntry(exe)}, func(a *App, ui *fakeUI, c *Core) { a.Main() })
		shot("3-problems", &fakeFW{fwOff: true, others: []*fakeRule{
			{name: "all", display: "Allow everything from anywhere (created by old admin)", source: "Local", open: true, enabled: true, ports: "Any"},
			{name: "g", display: "Revit from GPO", source: "GroupPolicy", open: true, enabled: true},
		}}, ir, []Entry{TCP(808)}, func(a *App, ui *fakeUI, c *Core) {
			a.Main()
			offline(t, c)
			c.SaveCountries([]string{"IR", "DE"})
			a.Fix(Problem{Kind: FixUpdateList})
		})
		shot("4-firewall-off", &fakeFW{fwOff: true}, ir, []Entry{TCP(808), UDP(1194)}, nil)
		shot("5-block", &fakeFW{others: []*fakeRule{{name: "b", display: "Block Revit (old test)", source: "Local", open: true, enabled: true, block: true}}}, ir, []Entry{TCP(808)},
			func(a *App, ui *fakeUI, c *Core) { a.Main() })
		shot("6-update-failed", &fakeFW{updateFail: true}, ir, []Entry{TCP(808)}, func(a *App, ui *fakeUI, c *Core) {
			a.Main()
			c.RunUpdate()
		})
	}
	lang = "fa"
	b, _ := json.MarshalIndent(views, "", " ")
	os.WriteFile(out, b, 0o644)
}
