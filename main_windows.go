//go:build windows

// CountryIPFilter.exe - opens chosen TCP/UDP ports and programs of this
// server only for the IPv4 ranges of chosen countries, using Windows
// Firewall. No installation: double-click.
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var Version = "dev"

func main() {
	// load system DLLs only from System32
	if p := kernel32.NewProc("SetDefaultDllDirectories"); p.Find() == nil {
		p.Call(0x00000800)
	}
	runtime.LockOSThread()
	restart := false
	for _, a := range os.Args[1:] {
		if strings.EqualFold(a, "--restart") {
			restart = true // opened again after a language change
		}
	}
	lang = systemLang()

	self, err := os.Executable()
	if err != nil {
		messageBox(0, T("مسیر برنامه پیدا نشد: ")+err.Error(), appTitle(), MB_OK|MB_ICONERROR)
		return
	}
	exeDir := filepath.Dir(self)
	if runningFromZip(exeDir) {
		messageBox(0, T("برنامه از داخل فایل فشرده (zip) باز شده است.\r\n\r\n")+
			T("اول پوشه‌ی برنامه را از فایل zip بیرون بکشید (مثلاً روی دسکتاپ) و بعد برنامه را از همان‌جا باز کنید. ")+
			T("همه‌ی فایل‌های برنامه کنار خودش، در پوشه‌ی data، نگه داشته می‌شوند."), appTitle(), MB_OK|MB_ICONWARNING)
		return
	}
	// everything the program keeps lives next to it, in the "data" folder
	dataDir := filepath.Join(exeDir, "data")
	if isReparse(dataDir) {
		messageBox(0, T("پوشه‌ی data کنار برنامه یک Symbolic Link یا Junction است، نه یک پوشه‌ی معمولی.\r\n\r\n")+
			T("برای امنیت، برنامه باز نمی‌شود. آن را پاک کنید و برنامه را دوباره باز کنید."), appTitle(), MB_OK|MB_ICONERROR)
		return
	}
	if l := (&Core{Dir: dataDir}).LoadLang(); l != "" {
		lang = l // the language chosen earlier, also for the messages below
	}
	// one window at a time; checked before touching any file, so a second
	// start never gets in the way of the running one
	got := singleInstance(`Global\CountryIPFilter`)
	for i := 0; restart && !got && i < 40; i++ { // the old window is still closing
		time.Sleep(250 * time.Millisecond)
		got = singleInstance(`Global\CountryIPFilter`)
	}
	if !got {
		if restart {
			messageBox(0, T("برنامه خودکار دوباره باز نشد. لطفاً چند لحظه بعد خودتان آن را باز کنید."), appTitle(), MB_OK|MB_ICONWARNING)
			return
		}
		if h, _, _ := pFindWindowW.Call(uintptr(unsafePtr(className)), 0); h != 0 {
			pShowWindow.Call(h, 9 /*SW_RESTORE*/)
			pSetForegroundWindow.Call(h)
		} else {
			messageBox(0, T("این برنامه همین حالا باز است (شاید در Session یک کاربر دیگر روی همین سرور). اول آن را ببندید و بعد دوباره باز کنید."), appTitle(), MB_OK|MB_ICONINFO)
		}
		return
	}

	os.MkdirAll(dataDir, 0o755)
	// only Administrators may change the program and its data: a folder of
	// its own is locked as a whole, otherwise at least the data folder
	dataNote := ""
	shared := FolderShared(exeDir) || isReparse(exeDir)
	lock := exeDir
	if shared {
		lock = dataDir
	}
	lockFailed := false
	var skipped []string
	if err := secureData(lock); err != nil {
		dataNote = T("Permission های پوشه‌ی برنامه محدود نشد: ") + err.Error()
		lockFailed = !shared
		if !shared && secureData(dataDir) == nil {
			skipped = resetChildren(dataDir)
		}
	} else {
		skipped = resetChildren(lock) // files someone else made earlier lose their old rights
		if !ownedByAdmins(lock) {
			// the owner of a folder can always change its permissions again
			dataNote = T("Owner پوشه‌ی برنامه Administrators نشد")
			lockFailed = !shared
		}
	}
	if len(skipped) > 0 {
		lockFailed = true
		dataNote = T("Permission این فایل‌ها محدود نشد (Symbolic Link، Hard Link یا Access Denied): ") + strings.Join(skipped, " , ")
	}
	if isReparse(dataDir) {
		messageBox(0, T("پوشه‌ی data کنار برنامه یک Symbolic Link یا Junction است، نه یک پوشه‌ی معمولی.\r\n\r\n")+
			T("برای امنیت، برنامه باز نمی‌شود. آن را پاک کنید و برنامه را دوباره باز کنید."), appTitle(), MB_OK|MB_ICONERROR)
		return
	}
	core := &Core{
		Dir:    dataDir,
		ExeDir: exeDir,
		Run:    psRunner(),
		HTTP:   &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 20 * time.Second}},
	}

	pCoInitializeEx.Call(0, 0x2) // COINIT_APARTMENTTHREADED: needed by the "open file" window
	g := &gui{}
	theGUI = g
	if err := g.create(); err != nil {
		messageBox(0, T("پنجره‌ی برنامه باز نشد:\r\n")+err.Error(), appTitle(), MB_OK|MB_ICONERROR)
		return
	}
	app := &App{core: core, ui: g, FolderShared: shared, FolderLockFailed: lockFailed}
	core.Log = g.Log
	g.app = app
	core.logf("%s  v%s", AppName, Version)
	if dataNote != "" {
		core.logf("%s", dataNote)
	}
	g.work(func() { app.Refresh() })
	g.loop()
}

// systemLang: Persian when Windows is shown in Persian, English otherwise.
// Also Persian on a server in Iran with an English Windows (the usual case).
func systemLang() string {
	id, _, _ := kernel32.NewProc("GetUserDefaultUILanguage").Call()
	if id&0x3FF == 0x29 { // LANG_PERSIAN
		return "fa"
	}
	if lcid, _, _ := kernel32.NewProc("GetUserDefaultLCID").Call(); lcid&0x3FF == 0x29 {
		return "fa"
	}
	if geo, _, _ := kernel32.NewProc("GetUserGeoID").Call(16); uint32(geo) == 116 { // GEOCLASS_NATION, Iran
		return "fa"
	}
	return "en"
}
