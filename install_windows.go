//go:build windows

package main

// Installing to Program Files and uninstalling (from Settings, Apps).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	folderCommonPrograms = syscall.GUID{Data1: 0x0139D44E, Data2: 0x6AFE, Data3: 0x49F2, Data4: [8]byte{0x86, 0x90, 0x3D, 0xAF, 0xCA, 0xE6, 0xFF, 0xB8}}
	folderPublicDesktop  = syscall.GUID{Data1: 0xC4AA340D, Data2: 0xF20F, Data3: 0x4863, Data4: [8]byte{0xAF, 0xEF, 0xF8, 0x7E, 0xF2, 0xE6, 0xBA, 0x25}}
	pMoveFileExW         = kernel32.NewProc("MoveFileExW")
)

// installDir: C:\Program Files\CountryIPFilter ("" when unknown).
func installDir() string {
	pf := knownFolder(&folderProgramFiles)
	if pf == "" {
		return ""
	}
	return pf + `\CountryIPFilter`
}

// shortcutPaths: the Start menu and the Desktop of all users.
func shortcutPaths() []string {
	var out []string
	for _, id := range []*syscall.GUID{&folderCommonPrograms, &folderPublicDesktop} {
		if p := knownFolder(id); p != "" {
			out = append(out, p+`\Country IP Filter.lnk`)
		}
	}
	return out
}

// sameDir: the same folder (also through 8.3 names or another spelling).
func sameDir(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// offerInstall asks to install (or update) the program in Program Files.
// true: the installed copy was started and this one must close.
func offerInstall(self, exeDir, dir string) bool {
	q := T("برنامه روی این کامپیوتر نصب شود؟") + nl + nl +
		T("برنامه در این پوشه نصب می‌شود (فقط Administrators می‌توانند آن را تغییر دهند):") + nl + dir + nl + nl +
		T("یک Shortcut در منوی Start و روی Desktop ساخته می‌شود. حذف برنامه از Settings و بخش Apps انجام می‌شود.")
	if fileExists(dir + `\CountryIPFilter.exe`) {
		q = T("نسخه‌ی نصب‌شده‌ی برنامه با همین نسخه به‌روز شود؟") + nl + nl + dir
	}
	q += nl + nl + T("اگر No را بزنید، برنامه از همین‌جا باز می‌شود.")
	if messageBox(0, q, appTitle(), MB_YESNO|MB_ICONQUESTION) != IDYES {
		return false
	}
	if err := install(self, exeDir, dir); err != nil {
		messageBox(0, T("نصب انجام نشد:")+nl+err.Error()+nl+nl+T("برنامه از همین‌جا باز می‌شود."), appTitle(), MB_OK|MB_ICONERROR)
		return false
	}
	// the installed copy takes over the window
	if mutexHandle != 0 {
		pCloseHandle.Call(mutexHandle)
		mutexHandle = 0
	}
	exe := dir + `\CountryIPFilter.exe`
	r, _, _ := pShellExecuteW.Call(0, uintptr(unsafe.Pointer(u16("open"))), uintptr(unsafe.Pointer(u16(exe))), uintptr(unsafe.Pointer(u16("--restart"))), 0, 1)
	if r <= 32 {
		messageBox(0, T("برنامه نصب شد ولی خودکار باز نشد. آن را از منوی Start باز کنید."), appTitle(), MB_OK|MB_ICONINFO)
	}
	return true
}

// install copies the program, its guides and its settings, then adds the
// shortcuts and the entry in Settings, Apps.
func install(self, exeDir, dir string) error {
	if isReparse(dir) {
		return errors.New(dir + " is a link")
	}
	// a folder that is already there must have been made by Administrators
	if _, err := os.Lstat(dir); err == nil && !ownedByAdmins(dir) {
		return errors.New(dir + ": owner is not Administrators")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := secureData(dir); err != nil {
		return err
	}
	if !ownedByAdmins(dir) {
		return errors.New(dir + ": owner is not Administrators")
	}
	// an uninstall before the last restart: Windows would delete the new file
	out, err := psRunner(filepath.Join(dir, "data"))("pending", PendingScript(dir))
	if err == nil {
		err = checkOK(out)
	}
	if err != nil {
		return err
	}
	if strings.Contains(out, "IPF-PENDING") {
		return errors.New(T("برنامه قبلاً حذف شده و ویندوز هنوز Restart نشده. اول ویندوز را Restart کنید، بعد دوباره نصب کنید."))
	}
	if skipped := resetChildren(dir); len(skipped) > 0 {
		return errors.New("not safe: " + strings.Join(skipped, ", "))
	}
	b, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "CountryIPFilter.exe"), b); err != nil {
		return err
	}
	for _, g := range []string{"Guide.html", "Guide-fa.html"} {
		if b, err := os.ReadFile(filepath.Join(exeDir, g)); err == nil {
			writeFileAtomic(filepath.Join(dir, g), b)
		}
	}
	// the choices made so far go along (unless the installed copy has its own)
	for _, f := range []string{"ports.txt", "countries.txt", "settings.txt"} {
		src, dst := filepath.Join(exeDir, "data", f), filepath.Join(dir, "data", f)
		if b, err := os.ReadFile(src); err == nil && !fileExists(dst) {
			writeFileAtomic(dst, b)
		}
	}
	out, err = psRunner(filepath.Join(dir, "data"))("install", InstallScript(filepath.Join(dir, "CountryIPFilter.exe"), shortcutPaths(), Version))
	if err != nil {
		return err
	}
	return checkOK(out)
}

// uninstall runs from Settings, Apps ("CountryIPFilter.exe --uninstall").
func uninstall(self string) {
	dir := filepath.Dir(self)
	// only the installed copy in Program Files removes anything
	if want := installDir(); want == "" || !sameDir(dir, want) || isReparse(dir) {
		messageBox(0, T("فقط برنامه‌ی نصب‌شده را می‌شود حذف کرد. برای حذف، از Settings و بخش Apps استفاده کنید."), appTitle(), MB_OK|MB_ICONWARNING)
		return
	}
	run := psRunner(filepath.Join(dir, "data"))
	out, err := run("status", ProtectionOnScript())
	if err == nil {
		err = checkOK(out)
	}
	if err != nil {
		messageBox(0, T("وضعیت Windows Firewall خوانده نشد، پس برنامه حذف نشد:")+nl+err.Error(), appTitle(), MB_OK|MB_ICONERROR)
		return
	}
	if strings.Contains(out, "IPF-ON") {
		messageBox(0, T("محافظت (یا به‌روزرسانی خودکار آن) هنوز روشن است. اول آن را خاموش کنید تا Rule های قدیمی به حالت قبل برگردند:")+nl+nl+
			T("1.  برنامه را باز کنید.")+nl+
			T("2.  دکمه‌ی «%s» را بزنید.", T(MainOff))+nl+
			T("3.  دوباره برنامه را از Settings حذف کنید."), appTitle(), MB_OK|MB_ICONWARNING)
		return
	}
	if messageBox(0, T("برنامه از این کامپیوتر حذف شود؟")+nl+nl+dir, appTitle(), MB_YESNO|MB_ICONQUESTION) != IDYES {
		return
	}
	out, err = run("uninstall", UninstallScript(dir, shortcutPaths()))
	if err == nil {
		err = checkOK(out)
	}
	if err != nil {
		messageBox(0, T("حذف برنامه کامل انجام نشد:")+nl+err.Error(), appTitle(), MB_OK|MB_ICONERROR)
		return
	}
	// the running program file and the (then empty) folders go at the next restart
	for _, p := range []string{self, filepath.Join(dir, "data", "run"), filepath.Join(dir, "data"), dir} {
		pMoveFileExW.Call(uintptr(unsafe.Pointer(u16(p))), 0, 4 /*MOVEFILE_DELAY_UNTIL_REBOOT*/)
	}
	messageBox(0, T("برنامه حذف شد. آخرین فایل آن بعد از Restart بعدی ویندوز پاک می‌شود."), appTitle(), MB_OK|MB_ICONINFO)
}
