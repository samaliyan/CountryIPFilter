package main

// Runs the generated PowerShell in PowerShell 7 (pwsh) when it is installed:
// every script must parse, the merging of IP ranges must give exactly what
// the Go code gives, and the rule writer and the monthly update are run
// against fake firewall cmdlets.

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pwsh(t *testing.T) string {
	p, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not installed")
	}
	return p
}

func runPS(t *testing.T, script string) string {
	dir := t.TempDir()
	f := filepath.Join(dir, "s.ps1")
	if err := os.WriteFile(f, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(pwsh(t), "-NoProfile", "-NonInteractive", "-File", f).CombinedOutput()
	if err != nil {
		t.Fatalf("pwsh: %v\n%s", err, out)
	}
	return string(out)
}

func TestPSParse(t *testing.T) {
	pwsh(t)
	scripts := map[string]string{
		"status":    StatusScript(),
		"apply":     ApplyScript([]string{"5.0.0.0/24", "6.0.0.0/16"}, []Entry{TCP(808), UDP(53), AppEntry(`C:\it's\a.exe`)}, map[string]string{"CC": "IR", "OK": "x"}),
		"update":    UpdateScript(),
		"tags":      TagScript(map[string]string{"OFF": "abc", "SEEN": ""}),
		"rules":     setRulesScript([]string{"a", "b'c"}, true),
		"remove":    RemoveScript(),
		"removeold": RemoveOldScript(),
		"task":      ScheduleScript(),
		"untask":    UnscheduleScript(),
		"firewall":  EnableFirewallScript(),
		"download":  DownloadScript("IR"),
		"install":   InstallScript(`C:\Program Files\CountryIPFilter\CountryIPFilter.exe`, []string{`C:\it's\a.lnk`}, "4.0.2"),
		"uninstall": UninstallScript(`C:\Program Files\CountryIPFilter`, []string{`C:\a.lnk`}),
		"protected": ProtectionOnScript(),
		"pending":   PendingScript(`C:\Program Files\CountryIPFilter`),
	}
	var b strings.Builder
	for name, s := range scripts {
		fmt.Fprintf(&b, "$e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput(%s, [ref]$null, [ref]$e); if ($e.Count -gt 0) { Write-Output ('ERR %s ' + $e[0].Message + ' line ' + $e[0].Extent.StartLineNumber) } else { Write-Output 'OK %s' }\n", psQuote(s), name, name)
	}
	// update.ps1 exactly as written
	fmt.Fprintf(&b, "$e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput(%s, [ref]$null, [ref]$e); Write-Output ('TASKARGS ' + $e.Count)\n", psQuote(strings.TrimPrefix(string(taskScriptBytes()), "\uFEFF")))
	out := runPS(t, b.String())
	if strings.Contains(out, "ERR") || !strings.Contains(out, "TASKARGS 0") || strings.Count(out, "OK ") != len(scripts) {
		t.Fatalf("parse errors:\n%s", out)
	}
}

// The monthly task merges in PowerShell; the program in Go. Same result.
func TestPSAggregateMatchesGo(t *testing.T) {
	pwsh(t)
	r := rand.New(rand.NewSource(7))
	var cases [][]string
	for round := 0; round < 12; round++ {
		var in []string
		for i := 0; i < 300; i++ {
			bits := 8 + r.Intn(25)
			if round%2 == 0 {
				bits = 20 + r.Intn(5) // many neighbours: lots of merging
			}
			o1 := []int{2, 5, 10, 80, 172, 192, 100, 223, 224}[r.Intn(9)]
			in = append(in, prefix{start: uint32(o1)<<24 | uint32(r.Intn(1<<24)), bits: bits}.String())
		}
		in = append(in, "1.2.3.4/33", "300.1.1.1/8", "8.8.8.8/7", "x")
		cases = append(cases, in)
	}
	var b strings.Builder
	for i, in := range cases {
		fmt.Fprintf(&b, "$raw = %s\n%s", psArray(in), psAggregatePS)
		fmt.Fprintf(&b, "Write-Output ('CASE%d|' + ($a -join ',') + '|' + ([uint64]$addr))\n", i)
	}
	out := runPS(t, b.String())
	for i, in := range cases {
		want := Aggregate(in)
		line := ""
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, fmt.Sprintf("CASE%d|", i)) {
				line = strings.TrimSpace(l)
			}
		}
		f := strings.Split(line, "|")
		if len(f) != 3 {
			t.Fatalf("case %d: no output\n%s", i, out)
		}
		if f[1] != strings.Join(want, ",") {
			t.Fatalf("case %d: PowerShell %s\nGo %s", i, f[1], strings.Join(want, ","))
		}
		if f[2] != fmt.Sprint(addrTotal(want)) {
			t.Fatalf("case %d: addresses %s vs %d", i, f[2], addrTotal(want))
		}
	}
}

// fake NetSecurity cmdlets, enough for the rule writer and the monthly update
const psFakeFirewall = `
$global:rules = [ordered]@{}
$global:log = New-Object 'System.Collections.Generic.List[string]'
function Import-Module {}
function MakeRule($n, $g, $d, $proto, $ports, $prog, $addr) {
  $global:rules[$n] = [pscustomobject]@{ Name = $n; Group = $g; Description = $d; Protocol = $proto; LocalPort = @($ports); Program = $prog; RemoteAddress = @($addr); Enabled = 'True' }
}
function Get-NetFirewallRule {
  [CmdletBinding()] param($Group, $Name, $PolicyStore, $Direction, $Enabled, $Action)
  $all = @($global:rules.Values)
  if ($Name) { $all = @($all | Where-Object { $_.Name -eq $Name }) }
  if ($Group) { $all = @($all | Where-Object { $_.Group -eq $Group }) }
  if ($Name -and $all.Count -eq 0) { return $null }
  return $all
}
function Get-NetFirewallPortFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$r) process { [pscustomobject]@{ LocalPort = $r.LocalPort; Protocol = $r.Protocol } } }
function Get-NetFirewallApplicationFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$r) process { [pscustomobject]@{ Program = $r.Program } } }
function Set-NetFirewallRule {
  [CmdletBinding()] param($Name, $RemoteAddress, $LocalPort, $Protocol, $Program, $Description, $Direction, $Action, $Profile, $Enabled, $LocalAddress, $Service, $InterfaceType, $RemotePort, $Authentication, $Encryption, [ValidateSet('Block', 'Allow', 'DeferToUser', 'DeferToApp')]$EdgeTraversalPolicy)
  $r = $global:rules[$Name]
  if ($null -ne $Description) { $r.Description = $Description }
  if ($null -ne $RemoteAddress) { $r.RemoteAddress = @($RemoteAddress) }
  if ($null -ne $LocalPort) { $r.LocalPort = @($LocalPort) }
  if ($null -ne $Protocol) { $r.Protocol = $Protocol }
  if ($null -ne $Program) { $r.Program = $Program }
  if ($Protocol -eq 'Any' -and $LocalPort) { throw 'ports need a protocol' }
  $global:log.Add("SET $Name")
}
function New-NetFirewallRule {
  [CmdletBinding()] param($Name, $DisplayName, $Group, $Description, $Direction, $Protocol, $LocalPort, $Program, $RemoteAddress, $Action, $Profile, $Enabled)
  if (-not $Protocol) { $Protocol = 'Any'; $LocalPort = @('Any') }
  if (-not $Program) { $Program = 'Any' }
  MakeRule $Name $Group $Description $Protocol $LocalPort $Program $RemoteAddress
  $global:log.Add("NEW $Name")
  return $global:rules[$Name]
}
function Remove-NetFirewallRule {
  [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject, $Name)
  process {
    $n = $Name
    if ($InputObject) { $n = $InputObject.Name }
    $global:rules.Remove($n)
    $global:log.Add("DEL $n")
  }
}
function Invoke-RestMethod {
  [CmdletBinding()] param($Uri, [switch]$UseBasicParsing, $TimeoutSec, $Proxy)
  $cc = ($Uri -split 'resource=')[1]
  if ($global:changeCC) { foreach ($x in $global:rules.Values) { $x.Description = $x.Description -replace '\[CC=[^\]]*\]', '[CC=IR]' } }
  if (-not $global:lists.ContainsKey($cc)) { throw 'download failed' }
  if ($global:lists[$cc] -like '<*') { return $global:lists[$cc] }
  return ($global:lists[$cc] | ConvertFrom-Json)
}
function Dump {
  foreach ($r in $global:rules.Values) { Write-Output ('RULE|' + $r.Name + '|' + $r.Protocol + '|' + (@($r.LocalPort) -join ',') + '|' + $r.Program + '|' + @($r.RemoteAddress).Count + '|' + $r.Description) }
}
`

func psLists(m map[string]string) string {
	var b strings.Builder
	b.WriteString("$global:lists = @{}\n")
	for k, v := range m {
		fmt.Fprintf(&b, "$global:lists[%s] = %s\n", psQuote(k), psQuote(v))
	}
	return b.String()
}

type psRule struct {
	name, proto, ports, prog, desc string
	count                          int
}

func parseDump(out string) map[string]psRule {
	m := map[string]psRule{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimRight(l, "\r"), "|", 7)
		if len(f) == 7 && f[0] == "RULE" {
			var n int
			fmt.Sscan(f[5], &n)
			m[f[1]] = psRule{name: f[1], proto: f[2], ports: f[3], prog: f[4], count: n, desc: f[6]}
		}
	}
	return m
}

// The rule writer: sets for TCP, UDP and a program; stale rules removed; tags on the first rules.
func TestPSApplyScript(t *testing.T) {
	pwsh(t)
	var ranges []string
	for i := 0; i < 900; i++ {
		ranges = append(ranges, fmt.Sprintf("5.%d.%d.0/24", i/250, i%250))
	}
	pre := psFakeFirewall +
		// a rule of an old set (UDP) and an extra part of the TCP set must go; a program rule limited to TCP is made again
		"MakeRule 'CountryIPFilter-TCP-01' 'Country IP Filter' 'old [OFF=xyz]' 'TCP' @('808') 'Any' @('1.1.1.1')\n" +
		"MakeRule 'CountryIPFilter-TCP-09' 'Country IP Filter' 'old' 'TCP' @('808') 'Any' @('1.1.1.1')\n" +
		"MakeRule 'CountryIPFilter-UDP-01' 'Country IP Filter' 'old' 'UDP' @('53') 'Any' @('1.1.1.1')\n" +
		"MakeRule ('CountryIPFilter-' + '" + appID(`C:\a.exe`) + "' + '-01') 'Country IP Filter' 'old' 'TCP' @('80') 'C:\\a.exe' @('1.1.1.1')\n" +
		"MakeRule 'Other' 'Something' 'x' 'TCP' @('80') 'Any' @('Any')\n"
	script := pre + ApplyScript(ranges, []Entry{TCP(808), TCP(22), AppEntry(`C:\a.exe`)}, map[string]string{"CC": "IR,DE", "OK": "2026-01-01T00:00:00Z,900,230400"}) + "\nDump\n"
	out := runPS(t, script)
	if !strings.Contains(out, "IPF-OK") {
		t.Fatalf("no IPF-OK:\n%s", out)
	}
	rules := parseDump(out)
	app := "CountryIPFilter-" + appID(`C:\a.exe`)
	for _, n := range []string{"CountryIPFilter-TCP-01", "CountryIPFilter-TCP-02", "CountryIPFilter-TCP-03", app + "-01", app + "-02", app + "-03", "Other"} {
		if _, ok := rules[n]; !ok {
			t.Fatalf("missing %s:\n%s", n, out)
		}
	}
	if len(rules) != 7 {
		t.Fatalf("stale rules left:\n%s", out)
	}
	tcp1, a1, a2 := rules["CountryIPFilter-TCP-01"], rules[app+"-01"], rules[app+"-02"]
	if tcp1.ports != "808,22" && tcp1.ports != "22,808" || tcp1.count != 400 || rules["CountryIPFilter-TCP-03"].count != 100 {
		t.Fatalf("tcp set: %+v", tcp1)
	}
	if a1.proto != "Any" || a1.prog != `C:\a.exe` || a2.proto != "Any" {
		t.Fatalf("program set: %+v %+v", a1, a2)
	}
	// tags only on the first rules, the old record kept
	if !strings.Contains(tcp1.desc, "[OFF=xyz]") || !strings.Contains(tcp1.desc, "[CC=IR,DE]") || !strings.Contains(a1.desc, "[CC=IR,DE]") {
		t.Fatalf("tags: %q %q", tcp1.desc, a1.desc)
	}
}

// The monthly update, run as the scheduled task runs it.
func TestPSMonthlyUpdate(t *testing.T) {
	pwsh(t)
	small := ripeJSON(300, 2)
	start := func(okTag string) string {
		var addrs []string
		for i := 0; i < 1000; i++ {
			addrs = append(addrs, fmt.Sprintf("'%d.%d.0.0/22'", 2+i/250, i%250))
		}
		desc := "d [CC=IR,DE] [OK=" + okTag + "] [OFF=abc]"
		return psFakeFirewall +
			"MakeRule 'CountryIPFilter-TCP-01' 'Country IP Filter' '" + desc + "' 'TCP' @('808','22') 'Any' @(" + strings.Join(addrs[:400], ",") + ")\n" +
			"MakeRule 'CountryIPFilter-TCP-02' 'Country IP Filter' 'd' 'TCP' @('808','22') 'Any' @(" + strings.Join(addrs[400:800], ",") + ")\n" +
			"MakeRule 'CountryIPFilter-TCP-03' 'Country IP Filter' 'd' 'TCP' @('808','22') 'Any' @(" + strings.Join(addrs[800:], ",") + ")\n" +
			"MakeRule 'CountryIPFilter-UDP-01' 'Country IP Filter' '" + desc + "' 'UDP' @('1194') 'Any' @(" + strings.Join(addrs[:400], ",") + ")\n" +
			"MakeRule 'CountryIPFilter-APP-0a0b0c0d-01' 'Country IP Filter' '" + desc + "' 'Any' @('Any') 'C:\\r.exe' @(" + strings.Join(addrs[:400], ",") + ")\n"
	}
	run := func(pre string, lists map[string]string) (map[string]psRule, string) {
		out := runPS(t, pre+psLists(lists)+"& ([ScriptBlock]::Create("+psQuote(UpdateScript())+"))\nDump\n")
		return parseDump(out), out
	}
	last := func(r map[string]psRule) string {
		d := r["CountryIPFilter-TCP-01"].desc
		i := strings.Index(d, "[LAST=")
		if i < 0 {
			return ""
		}
		return d[i : i+strings.Index(d[i:], "]")+1]
	}
	okTag := fmt.Sprintf("2026-08-01T00:00:00Z,2600,%d", 2600*1024)

	// a good update, run the way the task runs it: update.ps1 as a script file
	f := filepath.Join(t.TempDir(), "update.ps1")
	os.WriteFile(f, taskScriptBytes(), 0o644)
	out0 := runPS(t, start(okTag)+psLists(lists)+"& "+psQuote(f)+"\nDump\n")
	if !strings.Contains(out0, "IPF-OK") || !strings.Contains(out0, ",OK,task]") {
		t.Fatalf("update.ps1 as a file:\n%s", out0)
	}
	// a good update: IR 1966 + DE 700 ranges, written to all three sets
	r, out := run(start(okTag), lists)
	if !strings.Contains(out, "IPF-OK") || !strings.HasSuffix(last(r), ",OK,task]") {
		t.Fatalf("update failed:\n%s", out)
	}
	total := func(prefix string) int {
		n := 0
		for name, x := range r {
			if strings.HasPrefix(name, prefix) {
				n += x.count
			}
		}
		return n
	}
	if total("CountryIPFilter-TCP-") != 2666 || total("CountryIPFilter-UDP-") != 2666 || total("CountryIPFilter-APP-0a0b0c0d-") != 2666 {
		t.Fatalf("sets: %d %d %d\n%s", total("CountryIPFilter-TCP-"), total("CountryIPFilter-UDP-"), total("CountryIPFilter-APP-0a0b0c0d-"), out)
	}
	if r["CountryIPFilter-APP-0a0b0c0d-02"].prog != `C:\r.exe` || r["CountryIPFilter-UDP-03"].ports != "1194" || r["CountryIPFilter-TCP-07"].ports != "808,22" {
		t.Fatalf("settings kept: %+v", r)
	}
	d := r["CountryIPFilter-TCP-01"].desc
	if !strings.Contains(d, fmt.Sprintf("[OK=")) || !strings.Contains(d, fmt.Sprintf(",2666,%d]", 2666*1024)) || !strings.Contains(d, "[OFF=abc]") {
		t.Fatalf("tags after update: %q", d)
	}

	// much smaller: refused, nothing changed
	r, _ = run(start(okTag), map[string]string{"IR": small, "DE": ripeJSON(10, 80)})
	if !strings.HasSuffix(last(r), ",FAIL,list]") || r["CountryIPFilter-TCP-03"].count != 200 {
		t.Fatalf("smaller list: %s %+v", last(r), r["CountryIPFilter-TCP-03"])
	}
	// one country fails to download: nothing changed
	r, _ = run(start(okTag), map[string]string{"IR": lists["IR"]})
	if !strings.HasSuffix(last(r), ",FAIL,download]") || len(r) != 5 {
		t.Fatalf("download: %s", last(r))
	}
	// a country with no ranges: refused
	r, _ = run(start(okTag), map[string]string{"IR": lists["IR"], "DE": ripeWrap(`"ipv4":[]`)})
	if !strings.HasSuffix(last(r), ",FAIL,list]") {
		t.Fatalf("empty country: %s", last(r))
	}
	// an answer without the list (a proxy page, or JSON without ipv4) is refused
	for _, bad := range []string{"<html>blocked</html>", ripeWrap(``), ripeWrap(`"ipv4":["bad","10.0.0.0/8"]`), ripeWrap(`"ipv4":["1.2.3.٤/24"]`)} {
		r, out = run(start(okTag), map[string]string{"IR": lists["IR"], "DE": bad})
		if !strings.HasSuffix(last(r), ",FAIL,list]") || r["CountryIPFilter-TCP-03"].count != 200 {
			t.Fatalf("%s: %s\n%s", bad, last(r), out)
		}
	}
	// old data, no date, or a date in the future: refused, nothing changed
	stale := func(d string) string {
		return strings.Replace(lists["DE"], lists["DE"][strings.Index(lists["DE"], `"query_time":"`)+14:strings.Index(lists["DE"], `"query_time":"`)+33], d, 1)
	}
	for _, bad := range []string{stale(time.Now().UTC().AddDate(0, 0, -40).Format("2006-01-02T15:04:05")), stale(time.Now().UTC().AddDate(0, 0, 5).Format("2006-01-02T15:04:05")), strings.Replace(lists["DE"], `"query_time"`, `"other"`, 1)} {
		r, out = run(start(okTag), map[string]string{"IR": lists["IR"], "DE": bad})
		if !strings.HasSuffix(last(r), ",FAIL,old]") || r["CountryIPFilter-TCP-03"].count != 200 {
			t.Fatalf("old list: %s\n%s", last(r), out)
		}
	}
	// 29 days old is still fine
	r, _ = run(start(okTag), map[string]string{"IR": lists["IR"], "DE": stale(time.Now().UTC().AddDate(0, 0, -29).Format("2006-01-02T15:04:05"))})
	if !strings.HasSuffix(last(r), ",OK,task]") {
		t.Fatalf("29 days: %s", last(r))
	}
	// one small country shrinking is caught even when the total looks fine
	perTag := okTag + "] [CCN=IR:" + fmt.Sprint(1966*1024) + ",DE:" + fmt.Sprint(700*1024)
	r, _ = run(start(perTag), map[string]string{"IR": lists["IR"], "DE": ripeJSON(300, 80)})
	if !strings.HasSuffix(last(r), ",FAIL,list]") {
		t.Fatalf("per-country shrink: %s", last(r))
	}
	r, _ = run(start(perTag), lists)
	if !strings.HasSuffix(last(r), ",OK,task]") || !strings.Contains(r["CountryIPFilter-TCP-01"].desc, fmt.Sprintf("[CCN=IR:%d,DE:%d]", 1966*1024, 700*1024)) {
		t.Fatalf("per-country ok: %s %s", last(r), r["CountryIPFilter-TCP-01"].desc)
	}
	// the program changed the countries while the task was downloading: the task leaves it alone
	r, _ = run(start(okTag)+"$global:changeCC = $true\n", lists)
	if last(r) != "" || r["CountryIPFilter-TCP-03"].count != 200 {
		t.Fatalf("changed meanwhile: the task must change nothing, not even the record: %s", last(r))
	}
	// no OK record: refused
	r, _ = run(strings.ReplaceAll(start(okTag), "[OK="+okTag+"]", ""), lists)
	if !strings.HasSuffix(last(r), ",FAIL,list]") {
		t.Fatalf("no OK: %s", last(r))
	}
	// ports changed to "Any" by hand: refused
	r, _ = run(start(okTag)+"$global:rules['CountryIPFilter-TCP-01'].LocalPort = @('Any')\n", lists)
	if !strings.HasSuffix(last(r), ",FAIL,ports]") {
		t.Fatalf("edited ports: %s", last(r))
	}
	// a version 3 record (no address count): compared by number of ranges
	r, _ = run(start("2026-08-01T00:00:00Z,2600"), lists)
	if !strings.HasSuffix(last(r), ",OK,task]") {
		t.Fatalf("old OK tag: %s", last(r))
	}
	// far bigger than before: refused
	r, _ = run(start(fmt.Sprintf("2026-08-01T00:00:00Z,1500,%d", 1500*1024)), lists)
	if !strings.HasSuffix(last(r), ",FAIL,list]") {
		t.Fatalf("far bigger: %s", last(r))
	}
	// no protection rules: the task does nothing
	out = runPS(t, psFakeFirewall+psLists(lists)+"& ([ScriptBlock]::Create("+psQuote(UpdateScript())+"))\nDump\n")
	if strings.Contains(out, "RULE|") {
		t.Fatal("rules made from nothing")
	}
}
