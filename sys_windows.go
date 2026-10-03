//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

func init() {
	// a mapped network drive (Z:\app.exe) is as unsafe as a \\server\share path
	remotePath = func(p string) bool {
		if len(p) < 3 || p[1] != ':' {
			return false
		}
		root, _ := syscall.UTF16PtrFromString(p[:3])
		t, _, _ := kernel32.NewProc("GetDriveTypeW").Call(uintptr(unsafe.Pointer(root)))
		return t == 4 // DRIVE_REMOTE
	}
}

func system32(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", name)
}

func hidden(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// psRunner runs a script with Windows PowerShell, without any visible
// window: the script is written as a plain .ps1 file into the program's
// own "run" folder and started with -File (no encoded command lines, which
// antivirus programs take for malware). While PowerShell runs, the file is
// held open so that nobody can change or delete it, and its content is
// checked against what was written before it runs.
func psRunner(dataDir string) Runner {
	runDir := filepath.Join(dataDir, "run")
	return func(name, script string) (string, error) {
		ps := system32(`WindowsPowerShell\v1.0\powershell.exe`)
		if _, err := os.Stat(ps); err != nil {
			ps = "powershell.exe"
		}
		limit := 5 * time.Minute
		switch name {
		case "apply", "remove", "remove-old", "rules", "tags":
			limit = 30 * time.Minute // a big country can need hundreds of rules
		case "status":
			limit = 10 * time.Minute
		case "update":
			limit = 60 * time.Minute // downloads, a wait for the lock, all rules
		}
		path, release, err := lockedScript(runDir, name, script)
		if err != nil {
			return "", fmt.Errorf("script file: %v", err)
		}
		defer release()
		run := func(args ...string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			cmd := exec.CommandContext(ctx, ps, append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"}, args...)...)
			cmd.WaitDelay = 10 * time.Second // a child left holding the output must not keep us waiting
			hidden(cmd)
			out, err := cmd.CombinedOutput()
			s := strings.ReplaceAll(string(out), "\r\n", "\n")
			if ctx.Err() == context.DeadlineExceeded {
				return s, errors.New(T("PowerShell بیش از %d دقیقه طول کشید و متوقف شد (%s)", int(limit.Minutes()), name))
			}
			if err != nil {
				return s, fmt.Errorf("%v: %s", err, lastLines(s, 5))
			}
			return s, nil
		}
		out, err := run("-File", path)
		if err != nil && policyBlocked(out) {
			// Group Policy forbids script files: run the same text as a command
			out, err = run("-Command", "& ([ScriptBlock]::Create([IO.File]::ReadAllText("+psQuote(path)+", [Text.Encoding]::UTF8)))")
		}
		return out, err
	}
}

// policyBlocked: PowerShell refused the file because of the execution policy.
func policyBlocked(out string) bool {
	o := strings.ToLower(out)
	// a refused script printed nothing of its own; the error names stay
	// English in every Windows language
	if strings.Contains(out, "IPF-") || strings.Contains(out, "|") {
		return false
	}
	return strings.Contains(o, "pssecurityexception") ||
		strings.Contains(o, "execution polic") || strings.Contains(o, "is not digitally signed") || strings.Contains(o, "running scripts is disabled")
}

// lockedScript writes the script (UTF-8 with BOM) to a new file, reopens it
// read-only without write or delete sharing, and checks the content. release
// closes and deletes it.
func lockedScript(dir, name, script string) (string, func(), error) {
	if isReparse(dir) {
		return "", nil, errors.New("the run folder is a link")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	var rnd [8]byte
	rand.Read(rnd[:])
	path := filepath.Join(dir, fmt.Sprintf("%s-%x.ps1", name, rnd))
	data := append([]byte("\uFEFF"), []byte(script)...)
	p, _ := syscall.UTF16PtrFromString(path)
	const (
		genericRead, genericWrite = 0x80000000, 0x40000000
		shareRead                 = 0x1
		createNew, openExisting   = 1, 3
		flagReparse               = 0x00200000
	)
	h, err := syscall.CreateFile(p, genericWrite, 0, nil, createNew, flagReparse, 0)
	if err != nil {
		return "", nil, err
	}
	var n uint32
	werr := syscall.WriteFile(h, data, &n, nil)
	syscall.CloseHandle(h)
	if werr != nil || int(n) != len(data) {
		os.Remove(path)
		return "", nil, fmt.Errorf("write: %v", werr)
	}
	r, err := syscall.CreateFile(p, genericRead, shareRead, nil, openExisting, flagReparse, 0)
	if err != nil {
		os.Remove(path)
		return "", nil, err
	}
	release := func() {
		syscall.CloseHandle(r)
		os.Remove(path)
	}
	got := make([]byte, len(data)+1)
	var m uint32
	if err := syscall.ReadFile(r, got, &m, nil); err != nil || int(m) != len(data) || string(got[:m]) != string(data) {
		release()
		return "", nil, errors.New("the script file was changed before it ran")
	}
	return path, release, nil
}

var folderProgramFiles = syscall.GUID{Data1: 0x905e63b6, Data2: 0xc1bf, Data3: 0x494e, Data4: [8]byte{0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a}}

// knownFolder: the real path of a Windows folder (not from an environment
// variable, which the user could change).
func knownFolder(id *syscall.GUID) string {
	p := syscall.NewLazyDLL("shell32.dll").NewProc("SHGetKnownFolderPath")
	if p.Find() != nil {
		return ""
	}
	var out *uint16
	if r, _, _ := p.Call(uintptr(unsafe.Pointer(id)), 0, 0, uintptr(unsafe.Pointer(&out))); r != 0 || out == nil {
		return ""
	}
	defer syscall.NewLazyDLL("ole32.dll").NewProc("CoTaskMemFree").Call(uintptr(unsafe.Pointer(out)))
	var buf []uint16
	for q := unsafe.Pointer(out); ; q = unsafe.Add(q, 2) {
		c := *(*uint16)(q)
		if c == 0 || len(buf) > 1000 {
			break
		}
		buf = append(buf, c)
	}
	return string(utf16.Decode(buf))
}

func init() {
	// update.ps1 runs as SYSTEM: its folder is locked to Administrators and
	// SYSTEM (everyone else may only read) before the file is written
	// without the real Program Files folder the task is not set up at all
	taskDir = ""
	if pf := knownFolder(&folderProgramFiles); pf != "" {
		taskDir = pf + `\Country IP Filter Update`
	}
	writeTaskFile = func(dir, name string, data []byte) error {
		if dir == "" {
			return errors.New("the Program Files folder was not found")
		}
		if isReparse(dir) {
			return errors.New(dir + " is a link")
		}
		// a folder that already exists must have been made by Administrators
		if _, err := os.Lstat(dir); err == nil && !ownedByAdmins(dir) {
			return errors.New(dir + " was not made by Administrators; delete it and try again")
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
		if skipped := resetChildren(dir); len(skipped) > 0 {
			return errors.New("not safe: " + strings.Join(skipped, ", "))
		}
		return writeFileAtomic(filepath.Join(dir, name), data)
	}
}

// secureData lets only Administrators and SYSTEM change the data folder
// (everyone may read it), and makes Administrators its owner.
func secureData(dir string) error {
	enablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege")
	sd, err := syscall.UTF16PtrFromString("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)")
	if err != nil {
		return err
	}
	var psd uintptr
	if r, _, e := pConvertSDDL.Call(uintptr(unsafe.Pointer(sd)), 1, uintptr(unsafe.Pointer(&psd)), 0); r == 0 {
		return e
	}
	defer pLocalFree.Call(psd)
	var owner, dacl uintptr
	var present, def int32
	if r, _, e := pGetSDOwner.Call(psd, uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&def))); r == 0 {
		return e
	}
	if r, _, e := pGetSDDacl.Call(psd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&def))); r == 0 {
		return e
	}
	path, _ := syscall.UTF16PtrFromString(dir)
	const (
		seFileObject  = 1
		ownerInfo     = 0x1
		daclInfo      = 0x4
		protectedDacl = 0x80000000
	)
	if r, _, _ := pSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(path)), seFileObject, ownerInfo|daclInfo|protectedDacl, owner, 0, dacl, 0); r == 0 {
		return nil
	}
	// setting the owner can be refused; the permissions alone still help
	if r, _, _ := pSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(path)), seFileObject, daclInfo|protectedDacl, 0, 0, dacl, 0); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

var (
	advapi32              = syscall.NewLazyDLL("advapi32.dll")
	pConvertSDDL          = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	pGetSDOwner           = advapi32.NewProc("GetSecurityDescriptorOwner")
	pGetSDDacl            = advapi32.NewProc("GetSecurityDescriptorDacl")
	pSetNamedSecurityInfo = advapi32.NewProc("SetNamedSecurityInfoW")
	pLocalFree            = kernel32.NewProc("LocalFree")
)

// isReparse: a symbolic link or junction (someone could redirect our files).
func isReparse(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return true
	}
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok && d.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return true
	}
	return false
}

// runningFromZip: Windows runs an exe opened inside a zip from a temp folder.
func runningFromZip(dir string) bool {
	d := strings.ToLower(dir)
	tmp := strings.ToLower(os.Getenv("TEMP"))
	return (tmp != "" && strings.HasPrefix(d, tmp)) || strings.Contains(d, `\temp\`) && strings.Contains(d, ".zip")
}

// ownedByAdmins: the owner of the file or folder is Administrators or SYSTEM.
func ownedByAdmins(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var owner, psd uintptr
	const seFileObject, ownerInfo = 1, 0x1
	if r, _, _ := pGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(p)), seFileObject, ownerInfo, uintptr(unsafe.Pointer(&owner)), 0, 0, 0, uintptr(unsafe.Pointer(&psd))); r != 0 {
		return false
	}
	defer pLocalFree.Call(psd)
	var str *uint16
	if r, _, _ := pConvertSidToStringSid.Call(owner, uintptr(unsafe.Pointer(&str))); r == 0 {
		return false
	}
	defer pLocalFree.Call(uintptr(unsafe.Pointer(str)))
	var buf []uint16
	for q := unsafe.Pointer(str); ; q = unsafe.Add(q, 2) {
		c := *(*uint16)(q)
		if c == 0 || len(buf) > 200 {
			break
		}
		buf = append(buf, c)
	}
	sid := string(utf16.Decode(buf))
	return sid == "S-1-5-32-544" || sid == "S-1-5-18"
}

// resetChildren gives the files directly inside dir (and those in its
// "data" folder) the owner Administrators and only the inherited permissions
// of dir, so nobody keeps rights they had before the folder was locked.
// Each entry is opened first and held open without delete sharing, so it
// cannot be renamed or swapped while it is changed. Links, junctions and
// files with more than one name (hard links) are never changed or deleted:
// they are returned, and the window reports that the folder is not safe.
func resetChildren(dir string) (skipped []string) {
	enablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege")
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			path := filepath.Join(d, e.Name())
			isDir, ok := resetOne(path)
			if !ok {
				skipped = append(skipped, path)
				continue
			}
			if isDir && depth == 0 && strings.EqualFold(e.Name(), "data") {
				walk(path, 1)
			}
		}
	}
	walk(dir, 0)
	return skipped
}

// resetOne: see resetChildren. ok=false when the entry was not reset.
func resetOne(path string) (isDir, ok bool) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, false
	}
	const (
		readControl             = 0x20000 | 0x1 // with FILE_READ_DATA, so the share mode below is enforced
		shareReadWrite          = 0x3           // no FILE_SHARE_DELETE: nobody can rename or delete it meanwhile
		openExisting            = 3
		flagBackup, flagReparse = 0x02000000, 0x00200000
		attrDir, attrReparse    = 0x10, 0x400
	)
	h, _, _ := pCreateFileW.Call(uintptr(unsafe.Pointer(p)), readControl, shareReadWrite, 0, openExisting, flagBackup|flagReparse, 0)
	if h == 0 || h == ^uintptr(0) {
		return false, false
	}
	defer pCloseHandle.Call(h)
	var info struct {
		Attr                             uint32
		Create, Access, Write            [2]uint32
		Serial, SizeHigh, SizeLow, Links uint32
		IndexHigh, IndexLow              uint32
	}
	if r, _, _ := pGetFileInformationByHandle.Call(h, uintptr(unsafe.Pointer(&info))); r == 0 {
		return false, false
	}
	isDir = info.Attr&attrDir != 0
	if info.Attr&attrReparse != 0 || (!isDir && info.Links != 1) {
		return isDir, false
	}
	// the owner first (take ownership works whatever the permissions say),
	// then only the permissions inherited from the locked folder
	if applySDDL(path, "O:BA", 0x1) != nil {
		return isDir, false
	}
	if applySDDL(path, "D:", 0x4|0x20000000) != nil { // DACL | UNPROTECTED_DACL: inherit from the parent
		return isDir, false
	}
	return isDir, true
}

// applySDDL sets the owner (info 0x1) or the DACL (info 0x4 ...) of a path.
func applySDDL(path, sddl string, info uintptr) error {
	sd, _ := syscall.UTF16PtrFromString(sddl)
	var psd uintptr
	if r, _, e := pConvertSDDL.Call(uintptr(unsafe.Pointer(sd)), 1, uintptr(unsafe.Pointer(&psd)), 0); r == 0 {
		return e
	}
	defer pLocalFree.Call(psd)
	var owner, dacl uintptr
	var present, def int32
	if info&0x1 != 0 {
		if r, _, e := pGetSDOwner.Call(psd, uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&def))); r == 0 || owner == 0 {
			return e
		}
	} else {
		if r, _, e := pGetSDDacl.Call(psd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&def))); r == 0 || dacl == 0 {
			return e // never set a missing (NULL) DACL
		}
	}
	p, _ := syscall.UTF16PtrFromString(path)
	if r, _, _ := pSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(p)), 1, info, owner, 0, dacl, 0); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// enablePrivileges switches on privileges the Administrator token has but
// keeps off (needed to take ownership of files someone else locked).
func enablePrivileges(names ...string) {
	proc, _, _ := pGetCurrentProcess.Call()
	var tok uintptr
	const adjust, query = 0x20, 0x8
	if r, _, _ := pOpenProcessToken.Call(proc, adjust|query, uintptr(unsafe.Pointer(&tok))); r == 0 {
		return
	}
	defer pCloseHandle.Call(tok)
	for _, n := range names {
		var tp struct {
			Count      uint32
			Low, High  uint32
			Attributes uint32
		}
		np, _ := syscall.UTF16PtrFromString(n)
		if r, _, _ := pLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(np)), uintptr(unsafe.Pointer(&tp.Low))); r == 0 {
			continue
		}
		tp.Count, tp.Attributes = 1, 0x2 // SE_PRIVILEGE_ENABLED
		pAdjustTokenPrivileges.Call(tok, 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	}
}

var (
	pGetCurrentProcess          = kernel32.NewProc("GetCurrentProcess")
	pOpenProcessToken           = advapi32.NewProc("OpenProcessToken")
	pLookupPrivilegeValue       = advapi32.NewProc("LookupPrivilegeValueW")
	pAdjustTokenPrivileges      = advapi32.NewProc("AdjustTokenPrivileges")
	pCreateFileW                = kernel32.NewProc("CreateFileW")
	pGetFileInformationByHandle = kernel32.NewProc("GetFileInformationByHandle")
	pGetNamedSecurityInfo       = advapi32.NewProc("GetNamedSecurityInfoW")
	pConvertSidToStringSid      = advapi32.NewProc("ConvertSidToStringSidW")
)

var mutexHandle uintptr

// singleInstance returns false if the program is already running.
func singleInstance(name string) bool {
	h, _, err := pCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(u16(name))))
	if h == 0 {
		// typically "access denied": the monthly update (SYSTEM) holds it
		return false
	}
	if e, ok := err.(syscall.Errno); ok && e == ERROR_ALREADY_EXISTS {
		pCloseHandle.Call(h)
		return false
	}
	mutexHandle = h
	return true
}
