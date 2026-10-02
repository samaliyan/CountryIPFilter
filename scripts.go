package main

// The PowerShell scripts. Every script that changes the firewall takes the
// lock first; every script prints IPF-OK at its end, so a script that died
// halfway is never taken for a success. Text that may be non-ASCII is printed
// as Base64 of UTF-8 so the console code page cannot damage it.

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// psQuote: PowerShell also treats the curly quotes as single quotes.
func psQuote(s string) string {
	for _, q := range []string{"'", "‘", "’", "‚", "‛"} {
		s = strings.ReplaceAll(s, q, q+q)
	}
	return "'" + s + "'"
}

func psArray(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = psQuote(s)
	}
	return "@(" + strings.Join(q, ",") + ")"
}

func portList(p []int) []string {
	out := make([]string, len(p))
	for i, n := range p {
		out[i] = strconv.Itoa(n)
	}
	return out
}

// psCommon: helpers every script uses. SetTag writes one [KEY=value] piece
// into the Description of the first two rules of every rule set (so losing
// one rule loses nothing). Lock makes the program and the monthly task wait for
// each other.
const psCommon = "$ErrorActionPreference = 'Stop'\r\n" +
	"$ProgressPreference = 'SilentlyContinue'\r\n" +
	"Import-Module NetSecurity\r\n" +
	"function TagRules { @(Get-NetFirewallRule -Group 'Country IP Filter' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^CountryIPFilter-.+-0[12]$' } | Sort-Object Name) }\r\n" +
	"function SetTag($k, $v) {\r\n" +
	"  foreach ($r in (TagRules)) {\r\n" +
	"    $d = (\"$($r.Description)\" -replace ('\\s*\\[' + $k + '=[^\\]]*\\]'), '')\r\n" +
	"    if (\"$v\" -ne '') { $d = $d + ' [' + $k + '=' + $v + ']' }\r\n" +
	"    Set-NetFirewallRule -Name $r.Name -Description $d\r\n" +
	"  }\r\n" +
	"}\r\n" +
	"function GetTag($k) {\r\n" +
	"  foreach ($r in (TagRules)) {\r\n" +
	"    if (\"$($r.Description)\" -match ('\\[' + $k + '=([^\\]]*)\\]')) { return $Matches[1] }\r\n" +
	"  }\r\n" +
	"  return ''\r\n" +
	"}\r\n" +
	"function NowUtc { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }\r\n" +
	"function Lock {\r\n" +
	"  $global:ipfLock = $null\r\n" +
	"  try {\r\n" +
	"    $sec = New-Object System.Security.AccessControl.MutexSecurity\r\n" +
	"    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) { $sec.AddAccessRule((New-Object System.Security.AccessControl.MutexAccessRule((New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'Allow'))) }\r\n" +
	"    $created = $false\r\n" +
	"    $global:ipfLock = [System.Threading.Mutex]::new($false, 'Global\\CountryIPFilterRules', [ref]$created, $sec)\r\n" +
	"  } catch { Write-Output 'IPF-NOLOCK'; return }\r\n" +
	"  $got = $false\r\n" +
	"  try { $got = $global:ipfLock.WaitOne(150000) } catch [System.Threading.AbandonedMutexException] { $got = $true }\r\n" +
	"  if (-not $got) { throw 'Another Country IP Filter task is still changing the rules. Try again in a few minutes.' }\r\n" +
	"}\r\n"

const psHeader = psCommon +
	"try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}\r\n" +
	"function B64($x) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$x)) }\r\n"

// psWrite: the header of every script that changes something.
const psWrite = psHeader + "Lock\r\n"

// writeRulesPS is shared by ApplyScript and the monthly update: $a (the
// ranges) and $sets must be set. Existing rules are updated in place, so the
// chosen countries are never shut out while the rules are rewritten.
const writeRulesPS = `$names = @()
$keep = @(TagRules)
$desc = '` + ruleDesc + `'
if ($keep.Count -gt 0 -and "$($keep[0].Description)" -ne '') { $desc = "$($keep[0].Description)" }
$plain = ($desc -replace '\s*\[[A-Z]+=[^\]]*\]', '')
foreach ($s in $sets) {
  $k = 0
  for ($i = 0; $i -lt $a.Count; $i += 400) {
    $k++
    $n = 'CountryIPFilter-' + $s.Id + '-' + $k.ToString('00')
    $chunk = @($a[$i..([Math]::Min($i + 399, $a.Count - 1))])
    $names += $n
    $old = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
    if ($old -and $s.Prog -ne '' -and "$(($old | Get-NetFirewallPortFilter).Protocol)" -ne 'Any') {
      # a program rule must not be limited to one protocol: make it again
      Remove-NetFirewallRule -Name $n
      $old = $null
    }
    if ($old -and $s.Prog -ne '') {
      Set-NetFirewallRule -Name $n -RemoteAddress $chunk -Program $s.Prog -Direction Inbound -Action Allow -Profile Any -Enabled True -LocalAddress Any -Service Any -InterfaceType Any -Authentication NotRequired -Encryption NotRequired -EdgeTraversalPolicy Block
    } elseif ($old) {
      Set-NetFirewallRule -Name $n -RemoteAddress $chunk -LocalPort $s.Ports -Protocol $s.Proto -Direction Inbound -Action Allow -Profile Any -Enabled True -LocalAddress Any -Program Any -Service Any -InterfaceType Any -RemotePort Any -Authentication NotRequired -Encryption NotRequired -EdgeTraversalPolicy Block
    } elseif ($s.Prog -ne '') {
      New-NetFirewallRule -Name $n -DisplayName ('Country IP Filter - ' + $n) -Group 'Country IP Filter' -Description $(if ($k -le 2) { $desc } else { $plain }) -Direction Inbound -Program $s.Prog -RemoteAddress $chunk -Action Allow -Profile Any -Enabled True | Out-Null
    } else {
      New-NetFirewallRule -Name $n -DisplayName ('Country IP Filter - ' + $n) -Group 'Country IP Filter' -Description $(if ($k -le 2) { $desc } else { $plain }) -Direction Inbound -Protocol $s.Proto -LocalPort $s.Ports -RemoteAddress $chunk -Action Allow -Profile Any -Enabled True | Out-Null
    }
  }
}
Get-NetFirewallRule -Group 'Country IP Filter' -ErrorAction SilentlyContinue | Where-Object { $names -notcontains $_.Name } | Remove-NetFirewallRule
`

// psSets: the $sets the rule writer works on.
func psSets(sets []ruleSet) string {
	var items []string
	for _, s := range sets {
		items = append(items, "@{Id="+psQuote(s.ID)+"; Proto="+psQuote(s.Proto)+"; Ports="+psArray(portList(s.Ports))+"; Prog="+psQuote(s.Prog)+"}")
	}
	return "$sets = @(\r\n" + strings.Join(items, ",\r\n") + "\r\n)\r\n"
}

// ApplyScript makes the rules allow exactly ranges for the entries, then
// writes the tags (nil: tags stay as they are).
func ApplyScript(ranges []string, entries []Entry, tags map[string]string) string {
	var b strings.Builder
	b.WriteString(psWrite)
	b.WriteString(psSets(setsFor(entries)))
	b.WriteString("$a = @(\r\n")
	for i, r := range ranges {
		b.WriteString(psQuote(r))
		if i < len(ranges)-1 {
			b.WriteString(",")
		}
		if i%20 == 19 {
			b.WriteString("\r\n")
		}
	}
	b.WriteString(")\r\n")
	b.WriteString(writeRulesPS)
	var keys []string
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("SetTag " + psQuote(k) + " " + psQuote(tags[k]) + "\r\n")
	}
	b.WriteString("Write-Output 'IPF-OK'\r\n")
	return b.String()
}

// psAggregatePS: the same merging as Aggregate() in Go, for the a.b.c.d/n
// form RIPEstat uses. $raw: the ranges as downloaded; makes $a (sorted,
// merged) and $addr (number of addresses).
const psAggregatePS = `$keys = New-Object 'System.Collections.Generic.List[double]'
# private, loopback, multicast ...: never part of a country list (start, size)
$reserved = @(@(0, 16777216), @(167772160, 16777216), @(1681915904, 4194304), @(2130706432, 16777216), @(2851995648, 65536), @(2886729728, 1048576), @(3232235520, 65536), @(3758096384, 536870912))
foreach ($x in $raw) {
  if ("$x" -cmatch '^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$') {
    $o1 = [int]$Matches[1]; $o2 = [int]$Matches[2]; $o3 = [int]$Matches[3]; $o4 = [int]$Matches[4]; $p = [int]$Matches[5]
    if ($o1 -gt 255 -or $o2 -gt 255 -or $o3 -gt 255 -or $o4 -gt 255 -or $p -lt 8 -or $p -gt 32) { continue }
    $v = [double]$o1 * 16777216 + [double]$o2 * 65536 + [double]$o3 * 256 + [double]$o4
    $sz = [Math]::Pow(2, 32 - $p)
    $v = $v - ($v % $sz)
    $bad = $false
    foreach ($r in $reserved) { if ($v -lt $r[0] + $r[1] -and $v + $sz -gt $r[0]) { $bad = $true } }
    if ($bad) { continue }
    $keys.Add($v * 64 + $p)
  }
}
$arr = $keys.ToArray()
[Array]::Sort($arr)
$st = New-Object 'System.Collections.Generic.List[double]'
$bt = New-Object 'System.Collections.Generic.List[int]'
foreach ($k in $arr) {
  $b0 = [int]($k % 64)
  $s0 = ($k - $b0) / 64
  $n = $st.Count
  if ($n -gt 0 -and $s0 -ge $st[$n - 1] -and $s0 -lt $st[$n - 1] + [Math]::Pow(2, 32 - $bt[$n - 1])) { continue }
  $st.Add($s0); $bt.Add($b0)
  while ($st.Count -ge 2) {
    $n = $st.Count
    $b1 = $bt[$n - 2]
    if ($b1 -ne $bt[$n - 1] -or $b1 -le 8) { break }
    $sz = [Math]::Pow(2, 32 - $b1)
    if (($st[$n - 2] % ($sz * 2)) -ne 0 -or $st[$n - 1] -ne $st[$n - 2] + $sz) { break }
    $st.RemoveAt($n - 1); $bt.RemoveAt($n - 1); $bt[$n - 2] = $b1 - 1
  }
}
$addr = [double]0
$out = New-Object 'System.Collections.Generic.List[string]'
for ($i = 0; $i -lt $st.Count; $i++) {
  $v = $st[$i]
  $out.Add(('{0}.{1}.{2}.{3}/{4}' -f [int][Math]::Floor($v / 16777216), [int]([Math]::Floor($v / 65536) % 256), [int]([Math]::Floor($v / 256) % 256), [int]($v % 256), $bt[$i]))
  $addr += [Math]::Pow(2, 32 - $bt[$i])
}
$a = @($out)
`

// UpdateScript is what the monthly scheduled task runs (as SYSTEM, with no
// program file involved): download the lists of the countries recorded in
// the rules, check, rewrite every rule set as it is, record the result.
// A new list must not be much smaller (or far bigger) than the current one;
// otherwise nothing is changed.
func UpdateScript() string {
	return psCommon + `if (@(Get-NetFirewallRule -Group 'Country IP Filter' -ErrorAction SilentlyContinue).Count -eq 0) { return }
function Fail($why) { try { Lock; SetTag 'LAST' ((NowUtc) + ',FAIL,' + $why) } catch {} }
$ccText = "$(GetTag 'CC')"
$ok0 = "$(GetTag 'OK')"
$cc = @($ccText -split ',' | Where-Object { $_ -cmatch '^[A-Z]{2}$' })
if ($cc.Count -eq 0) { Fail 'list'; return }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}
$px = ''
try { $px = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((GetTag 'PROXY'))) } catch {}
$all = New-Object 'System.Collections.Generic.List[string]'
$per = @{}
foreach ($c in $cc) {
  $u = '` + ripeBase + `' + $c
  $j = $null
  try {
    if ($px -match '^https?://[A-Za-z0-9.\-]+(:\d+)?/?$') { try { $j = Invoke-RestMethod -Uri $u -UseBasicParsing -TimeoutSec 100 -Proxy $px } catch {} }
    if (-not $j) { $j = Invoke-RestMethod -Uri $u -UseBasicParsing -TimeoutSec 100 }
  } catch { Fail 'download'; return }
  # a page from a proxy, or an answer without the list, is not a list
  $list = $null
  if ($j -isnot [string]) { try { $list = $j.data.resources.ipv4 } catch {} }
  if ($null -eq $list) { Fail 'list'; return }
  $raw = @($list | ForEach-Object { "$_" })
  try {
` + psAggregatePS + `  } catch { Fail 'list'; return }
  if ($a.Count -lt 1) { Fail 'list'; return }
  $per[$c] = $addr
  foreach ($x in $a) { $all.Add($x) }
}
$raw = @($all)
try {
` + psAggregatePS + `} catch { Fail 'list'; return }
$lockErr = $null
try { Lock } catch { $lockErr = $_ }
if ($lockErr) { try { SetTag 'LAST' ((NowUtc) + ',FAIL,lock') } catch {}; return }
# the program changed the countries or the list meanwhile: leave its work alone
# (its own record of what it did is the right one: write nothing)
if ("$(GetTag 'CC')" -ne $ccText -or "$(GetTag 'OK')" -ne $ok0) { return }
if ($ok0 -cnotmatch '^[^,]*,([0-9]+)(,([0-9]+))?$') { SetTag 'LAST' ((NowUtc) + ',FAIL,list'); return }
$old = [int]$Matches[1]; $oldAddr = [double]0
if ($Matches[3]) { $oldAddr = [double]$Matches[3] }
function Near($new, $was) { ($new -ge $was * 0.85) -and ($new -le $was * 1.5 + 65536) }
$bad = ($a.Count -lt 1) -or ($addr -gt ` + strconv.Itoa(maxAddr) + `)
if ($oldAddr -gt 0) { $bad = $bad -or -not (Near $addr $oldAddr) } else { $bad = $bad -or ($a.Count -lt $old * 0.85) }
# every country on its own: a small one must not vanish behind a big one
foreach ($p in @("$(GetTag 'CCN')" -split ',')) {
  if ($p -cmatch '^([A-Z]{2}):([0-9]+)$' -and $per.ContainsKey($Matches[1]) -and [double]$Matches[2] -gt 0) {
    if (-not (Near $per[$Matches[1]] ([double]$Matches[2]))) { $bad = $true }
  }
}
if ($bad) { SetTag 'LAST' ((NowUtc) + ',FAIL,list'); return }
$first = @{}
foreach ($r in @(Get-NetFirewallRule -Group 'Country IP Filter' -ErrorAction SilentlyContinue | Sort-Object Name)) {
  if ($r.Name -cmatch '^CountryIPFilter-(.+)-([0-9]{2,})$' -and -not $first.ContainsKey($Matches[1])) { $first[$Matches[1]] = $r }
}
$sets = @()
foreach ($id in @($first.Keys | Sort-Object)) {
  $r = $first[$id]
  if ($id -ceq 'TCP' -or $id -ceq 'UDP') {
    $ports = @(($r | Get-NetFirewallPortFilter).LocalPort | ForEach-Object { "$_" })
    if ($ports.Count -eq 0 -or @($ports | Where-Object { $_ -cnotmatch '^[0-9]{1,5}$' }).Count -gt 0) { SetTag 'LAST' ((NowUtc) + ',FAIL,ports'); return }
    $sets += @{ Id = $id; Proto = $id; Ports = $ports; Prog = '' }
  } elseif ($id -cmatch '^APP-[0-9a-f]{8}$') {
    $prog = "$(($r | Get-NetFirewallApplicationFilter).Program)"
    if ($prog -eq '' -or $prog -eq 'Any' -or $prog -eq 'System') { SetTag 'LAST' ((NowUtc) + ',FAIL,ports'); return }
    $sets += @{ Id = $id; Proto = 'Any'; Ports = @(); Prog = $prog }
  }
}
if ($sets.Count -eq 0) { SetTag 'LAST' ((NowUtc) + ',FAIL,ports'); return }
$ccn = @($cc | ForEach-Object { $_ + ':' + ([uint64]$per[$_]).ToString([Globalization.CultureInfo]::InvariantCulture) }) -join ','
try {
` + writeRulesPS + `  SetTag 'OK' ((NowUtc) + ',' + $a.Count + ',' + ([uint64]$addr).ToString([Globalization.CultureInfo]::InvariantCulture))
  SetTag 'CCN' $ccn
  SetTag 'LAST' ((NowUtc) + ',OK,task')
  Write-Output 'IPF-OK'
} catch { SetTag 'LAST' ((NowUtc) + ',FAIL,apply') }
`
}

// TaskArguments: the powershell.exe arguments of the scheduled task. The
// script travels as Base64 of UTF-8 (half the size of -EncodedCommand), so
// the task's command line stays short.
func TaskArguments() string {
	b := base64.StdEncoding.EncodeToString([]byte(UpdateScript()))
	return `-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + b + `'))))"`
}

// encodePS: Base64 of UTF-16LE, as powershell.exe -EncodedCommand wants.
func encodePS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[2*i] = byte(v)
		b[2*i+1] = byte(v >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func DownloadScript(cc string) string {
	return "$ErrorActionPreference = 'Stop'\r\n" +
		"try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}\r\n" +
		"$r = Invoke-WebRequest -Uri " + psQuote(RipeURL(cc)) + " -UseBasicParsing -TimeoutSec 120\r\n" +
		"Write-Output ('DATA|' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$r.Content)))\r\n" +
		"Write-Output 'IPF-OK'\r\n"
}

// StatusScript prints the active firewall profiles, our rules (and those of
// version 3), every listening TCP port and UDP endpoint with its program,
// every inbound rule that could matter (Go decides), and the scheduled tasks.
func StatusScript() string {
	return psHeader + `try { Write-Output ('ACTIVE|' + (Get-NetFirewallSetting -PolicyStore ActiveStore).ActiveProfile) } catch {}
Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { Write-Output ('PROFILE|' + $_.Name + '|' + $_.Enabled + '|' + $_.DefaultInboundAction + '|' + $_.AllowLocalFirewallRules + '|' + $_.AllowInboundRules) }
# every program that listens (not only on this computer itself)
$svcByPid = @{}
try { foreach ($s in @(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction Stop)) { $svcByPid[[int]$s.ProcessId] = @($svcByPid[[int]$s.ProcessId]) + $s.Name } } catch {}
$pathByPid = @{}
function PathOf($procId) {
  if ($procId -eq 4) { return 'System' }
  if (-not $pathByPid.ContainsKey($procId)) { $p = ''; try { $p = (Get-Process -Id $procId -ErrorAction Stop).Path } catch {}; $pathByPid[$procId] = $p }
  return $pathByPid[$procId]
}
$seen = @{}
foreach ($x in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
  $addr = "$($x.LocalAddress)"
  if ($addr -like '127.*' -or $addr -eq '::1') { continue }
  $procId = [int]$x.OwningProcess
  $key = "t$($x.LocalPort)/$procId"
  if ($seen.ContainsKey($key)) { continue }
  $seen[$key] = 1
  Write-Output ('LISTEN|' + $x.LocalPort + '|' + (B64 (PathOf $procId)) + '|' + (B64 ((@($svcByPid[$procId]) | Where-Object { $_ }) -join ',')))
}
foreach ($x in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
  $addr = "$($x.LocalAddress)"
  if ($addr -like '127.*' -or $addr -eq '::1') { continue }
  $procId = [int]$x.OwningProcess
  $key = "u$($x.LocalPort)/$procId"
  if ($seen.ContainsKey($key)) { continue }
  $seen[$key] = 1
  Write-Output ('LISTENU|' + $x.LocalPort + '|' + (B64 (PathOf $procId)) + '|' + (B64 ((@($svcByPid[$procId]) | Where-Object { $_ }) -join ',')))
}
$pfm = @{}; $afm = @{}; $apm = @{}; $svm = @{}; $itm = @{}; $ifm = @{}
$enabledRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -ErrorAction SilentlyContinue)
$disabledRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled False -ErrorAction SilentlyContinue)
function AddAll($map, $items) { foreach ($f in @($items)) { if (-not $map.ContainsKey($f.InstanceID)) { $map[$f.InstanceID] = $f } } }
$stores = @('ActiveStore')
if ($disabledRules.Count -gt 0) { $stores += 'PersistentStore' }
foreach ($store in $stores) {
  try { AddAll $pfm (Get-NetFirewallPortFilter -All -PolicyStore $store) } catch {}
  try { AddAll $afm (Get-NetFirewallAddressFilter -All -PolicyStore $store) } catch {}
  try { AddAll $apm (Get-NetFirewallApplicationFilter -All -PolicyStore $store) } catch {}
  try { AddAll $svm (Get-NetFirewallServiceFilter -All -PolicyStore $store) } catch {}
  try { AddAll $itm (Get-NetFirewallInterfaceTypeFilter -All -PolicyStore $store) } catch {}
  try { AddAll $ifm (Get-NetFirewallInterfaceFilter -All -PolicyStore $store) } catch {}
}
function Ours($r, $tag) {
  $id = $r.InstanceID
  $pf = $pfm[$id]; if (-not $pf) { $pf = $r | Get-NetFirewallPortFilter }
  $af = $afm[$id]; if (-not $af) { $af = $r | Get-NetFirewallAddressFilter }
  $ap = $apm[$id]; if (-not $ap) { $ap = $r | Get-NetFirewallApplicationFilter }
  $sv = $svm[$id]; if (-not $sv) { $sv = $r | Get-NetFirewallServiceFilter }
  $it = $itm[$id]; if (-not $it) { $it = $r | Get-NetFirewallInterfaceTypeFilter }
  $ra = @($af.RemoteAddress | ForEach-Object { "$_" })
  $wide = ($ra.Count -eq 0) -or ($ra -contains 'Any')
  $d = ''
  if ($r.Name -match '-0[12]$') { $d = "$($r.Description)" }
  Write-Output ($tag + '|' + $r.Name + '|' + $r.Enabled + '|' + (@($pf.LocalPort) -join ',') + '|' + $ra.Count + '|' + $wide + '|' + $pf.Protocol + '|' + (B64 $d) + '|' + $r.Action + '|' + $r.Direction + '|' + $r.Profile + '|' + (B64 (@($af.LocalAddress) -join ',')) + '|' + (B64 $ap.Program) + '|' + (B64 $sv.Service) + '|' + $it.InterfaceType + '|' + (B64 ($ra -join ',')) + '|' + (@($pf.RemotePort) -join ','))
}
foreach ($r in @(Get-NetFirewallRule -Group 'Country IP Filter' -ErrorAction SilentlyContinue)) { Ours $r 'OURS' }
foreach ($r in @(Get-NetFirewallRule -Group 'Iran IP Filter' -ErrorAction SilentlyContinue)) { Ours $r 'OLD' }
function Emit($r, $en) {
  if ($r.Group -eq 'Country IP Filter' -or $r.Group -eq 'Iran IP Filter') { return }
  $id = $r.InstanceID
  # rules of Windows store apps (Start, Your account, Teams ...) only let that one app in
  $dg = "$($r.DisplayGroup)"; $ds = "$($r.Description)"; $own = "$($r.Owner)"
  if ($own -ne '' -or $dg -like '@{*' -or $ds -like '@{*') { return }
  $ap = $apm[$id]; if (-not $ap) { $ap = $r | Get-NetFirewallApplicationFilter }
  $pkg = "$($ap.Package)"
  if ($pkg -ne '' -and $pkg -ne 'Any' -and $pkg -ne '*') { return }
  $pf = $pfm[$id]; if (-not $pf) { $pf = $r | Get-NetFirewallPortFilter }
  $af = $afm[$id]; if (-not $af) { $af = $r | Get-NetFirewallAddressFilter }
  $sv = $svm[$id]; if (-not $sv) { $sv = $r | Get-NetFirewallServiceFilter }
  $it = $itm[$id]; if (-not $it) { $it = $r | Get-NetFirewallInterfaceTypeFilter }
  $fi = $ifm[$id]; if (-not $fi) { $fi = $r | Get-NetFirewallInterfaceFilter }
  $prog = "$($ap.Program)"
  if ($prog -ne '' -and $prog -ne 'Any' -and $prog -ne 'System') { $prog = [Environment]::ExpandEnvironmentVariables($prog) }
  Write-Output ('RULE|' + (B64 $r.Name) + '|' + $r.PolicyStoreSourceType + '|' + $en + '|' + $pf.Protocol + '|' + (@($pf.LocalPort) -join ',') + '|' + (@($af.RemoteAddress) -join ',') + '|' + (B64 $prog) + '|' + (B64 $sv.Service) + '|' + (B64 $r.DisplayName) + '|' + $it.InterfaceType + '|' + (B64 (@($fi.InterfaceAlias) -join ',')) + '|' + $r.Action + '|' + $r.Profile + '|' + (B64 $r.DisplayGroup))
}
foreach ($r in $enabledRules) { Emit $r 'True' }
foreach ($r in $disabledRules) { Emit $r 'False' }
# the proxy Windows uses for the lists (the monthly task, as SYSTEM, has none of its own)
try { $u = New-Object Uri 'https://stat.ripe.net/'; $wp = [Net.WebRequest]::GetSystemWebProxy(); if (-not $wp.IsBypassed($u)) { $pu = $wp.GetProxy($u); if ($pu.Host -ne $u.Host) { Write-Output ('PROXY|' + (B64 $pu.AbsoluteUri)) } } } catch {}
$t = Get-ScheduledTask -TaskName '` + TaskName + `' -ErrorAction SilentlyContinue
Write-Output ('TASK|' + [bool]$t)
if ($t) { Write-Output ('TASKARGS|' + (B64 ("$(@($t.Actions)[0].Execute) $(@($t.Actions)[0].Arguments)"))) }
Write-Output ('OLDTASK|' + [bool](Get-ScheduledTask -TaskName '` + OldTask + `' -ErrorAction SilentlyContinue))
Write-Output 'IPF-OK'
`
}

// setRulesScript switches rules on or off by their exact name (Name
// patterns would treat [ and * as wildcards). A rule that no longer exists
// is reported as GONE.
func setRulesScript(names []string, enable bool) string {
	verb := "Disable-NetFirewallRule"
	if enable {
		verb = "Enable-NetFirewallRule"
	}
	return psWrite +
		"$all = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue)\r\n" +
		"foreach ($n in " + psArray(names) + ") {\r\n" +
		"  $r = @($all | Where-Object { $_.Name -ceq $n })\r\n" +
		"  if ($r.Count -eq 0) { Write-Output ('GONE|' + (B64 $n)); continue }\r\n" +
		"  try { $r | " + verb + " -ErrorAction Stop; Write-Output ('DONE|' + (B64 $n)) }\r\n" +
		"  catch { Write-Output ('FAIL|' + (B64 $n) + '|' + (B64 $_.Exception.Message)) }\r\n" +
		"}\r\n" +
		"Write-Output 'IPF-OK'\r\n"
}

// TagScript writes [KEY=value] pieces (value "" removes the piece).
func TagScript(tags map[string]string) string {
	var keys []string
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := psWrite + "if ((TagRules).Count -eq 0) { throw 'protection rules not found' }\r\n"
	for _, k := range keys {
		s += "SetTag " + psQuote(k) + " " + psQuote(tags[k]) + "\r\n"
	}
	return s + "Write-Output 'IPF-OK'\r\n"
}

func RemoveScript() string {
	return psWrite +
		"Get-NetFirewallRule -Group 'Country IP Filter' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\r\n" +
		"Write-Output 'IPF-OK'\r\n"
}

// RemoveOldScript removes the rules and the monthly task of version 3.
func RemoveOldScript() string {
	return psWrite +
		"Get-NetFirewallRule -Group " + psQuote(OldGroup) + " -ErrorAction SilentlyContinue | Remove-NetFirewallRule\r\n" +
		"Unregister-ScheduledTask -TaskName " + psQuote(OldTask) + " -Confirm:$false -ErrorAction SilentlyContinue\r\n" +
		"Write-Output 'IPF-OK'\r\n"
}

func ScheduleScript() string {
	return "$ErrorActionPreference = 'Stop'\r\n" +
		"$ps = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'\r\n" +
		"$a = New-ScheduledTaskAction -Execute $ps -Argument " + psQuote(TaskArguments()) + "\r\n" +
		"$t = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Friday -At '04:00'\r\n" +
		"$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 3)\r\n" +
		"$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\r\n" +
		"Register-ScheduledTask -TaskName " + psQuote(TaskName) + " -Description 'Refreshes the country IP ranges of the Country IP Filter firewall rules.' -Action $a -Trigger $t -Settings $s -Principal $p -Force | Out-Null\r\n" +
		"Write-Output 'IPF-OK'\r\n"
}

func UnscheduleScript() string {
	return "$ErrorActionPreference = 'Stop'\r\n" +
		"Unregister-ScheduledTask -TaskName " + psQuote(TaskName) + " -Confirm:$false -ErrorAction SilentlyContinue\r\n" +
		"Write-Output 'IPF-OK'\r\n"
}

func EnableFirewallScript() string {
	return psWrite +
		"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -AllowInboundRules True\r\n" +
		"try { SetTag 'FWON' '1' } catch {}\r\n" +
		"Write-Output 'IPF-OK'\r\n"
}
