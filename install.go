package main

// Installing: the program copies itself to Program Files (the only place
// where its folder is safe from other users), adds shortcuts and an entry in
// Settings, Apps. These are the PowerShell parts; the steps are in
// install_windows.go.

import "strings"

const (
	uninstallKey = `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CountryIPFilter`
	projectURL   = "https://github.com/samaliyan/CountryIPFilter"
)

// InstallScript makes the shortcuts and the entry in Settings, Apps.
func InstallScript(exe string, links []string, version string) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\r\n")
	b.WriteString("$exe = " + psQuote(exe) + "\r\n")
	b.WriteString("$sh = New-Object -ComObject WScript.Shell\r\n")
	for _, l := range links {
		b.WriteString("$s = $sh.CreateShortcut(" + psQuote(l) + "); $s.TargetPath = $exe; $s.WorkingDirectory = (Split-Path -Parent $exe); $s.IconLocation = $exe + ',0'; $s.Description = 'Country IP Filter'; $s.Save()\r\n")
	}
	b.WriteString("$k = " + psQuote(uninstallKey) + "\r\n")
	b.WriteString("New-Item -Path $k -Force | Out-Null\r\n")
	for _, kv := range [][2]string{
		{"DisplayName", AppName}, {"DisplayVersion", version}, {"Publisher", "Country IP Filter (open source)"},
		{"InstallLocation", dirOf(exe)}, {"DisplayIcon", exe}, {"UninstallString", `"` + exe + `" --uninstall`},
		{"URLInfoAbout", projectURL},
	} {
		b.WriteString("New-ItemProperty -Path $k -Name " + psQuote(kv[0]) + " -Value " + psQuote(kv[1]) + " -PropertyType String -Force | Out-Null\r\n")
	}
	b.WriteString("New-ItemProperty -Path $k -Name 'NoModify' -Value 1 -PropertyType DWord -Force | Out-Null\r\n")
	b.WriteString("New-ItemProperty -Path $k -Name 'NoRepair' -Value 1 -PropertyType DWord -Force | Out-Null\r\n")
	b.WriteString("Write-Output 'IPF-OK'\r\n")
	return b.String()
}

// ProtectionOnScript prints IPF-ON when protection rules (also those of
// version 3) or a monthly task exist. A failure to read stops the script, so
// it is never taken for "off".
func ProtectionOnScript() string {
	return "$ErrorActionPreference = 'Stop'\r\n" +
		"Import-Module NetSecurity\r\n" +
		"$n = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Group -eq " + psQuote(RuleGroup) + " -or $_.Group -eq " + psQuote(OldGroup) + " }).Count\r\n" +
		"$t = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq " + psQuote(TaskName) + " -or $_.TaskName -eq " + psQuote(OldTask) + " }).Count\r\n" +
		"if ($n -gt 0 -or $t -gt 0) { Write-Output 'IPF-ON' }\r\n" +
		"Write-Output 'IPF-OK'\r\n"
}

// PendingScript prints IPF-PENDING when Windows still has to delete files of
// dir at the next restart (left by an uninstall): installing now would lose
// the new program file at that restart.
func PendingScript(dir string) string {
	return "$ErrorActionPreference = 'Stop'\r\n" +
		"$p = @((Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)\r\n" +
		"$d = " + psQuote(strings.ToLower(dir)) + "\r\n" +
		"foreach ($x in $p) { if (\"$x\".ToLower().Contains($d)) { Write-Output 'IPF-PENDING'; break } }\r\n" +
		"Write-Output 'IPF-OK'\r\n"
}

// UninstallScript removes the shortcuts, the entry in Settings and the
// program's files by their exact names: never anything else, and folders
// only when they are empty afterwards. The program file itself goes when
// Windows restarts (it is running now).
func UninstallScript(dir string, links []string) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\r\n")
	b.WriteString("function DelFile($p) { if (Test-Path -LiteralPath $p -PathType Leaf) { Remove-Item -LiteralPath $p -Force } }\r\n")
	b.WriteString("function DelEmptyDir($p) { if ((Test-Path -LiteralPath $p -PathType Container) -and -not (((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -and @(Get-ChildItem -LiteralPath $p -Force).Count -eq 0) { Remove-Item -LiteralPath $p -Force } }\r\n")
	for _, l := range links {
		b.WriteString("DelFile " + psQuote(l) + "\r\n")
	}
	b.WriteString("if (Test-Path -LiteralPath " + psQuote(uninstallKey) + ") { Remove-Item -LiteralPath " + psQuote(uninstallKey) + " -Force }\r\n")
	data := dir + `\data`
	for _, f := range []string{dir + `\Guide.html`, dir + `\Guide-fa.html`, data + `\ports.txt`, data + `\countries.txt`, data + `\settings.txt`, data + `\log.txt`, data + `\log.txt.old`} {
		b.WriteString("DelFile " + psQuote(f) + "\r\n")
	}
	b.WriteString("DelEmptyDir " + psQuote(data+`\run`) + "\r\n")
	b.WriteString("DelEmptyDir " + psQuote(data) + "\r\n")
	b.WriteString("Write-Output 'IPF-OK'\r\n")
	return b.String()
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return p
}
