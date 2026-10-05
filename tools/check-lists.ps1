& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}
$cc = @()   # empty: the countries of the firewall rules. Or for example: $cc = @('IR')
$tmp = Join-Path $env:TEMP ("ipcheck-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {

function Fetch($url, $name) {
  $f = Join-Path $tmp $name
  $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 300 -OutFile $f -PassThru
  $lm = ''
  try { $lm = ([datetime]$r.Headers['Last-Modified']).ToUniversalTime().ToString('yyyy-MM-dd') } catch {}
  return @{ File = $f; Date = $lm }
}
function IpNum($s) {
  $p = $s.Trim().Split('.')
  if ($p.Count -ne 4) { throw "bad ip $s" }
  $n = [uint64]0
  foreach ($x in $p) { $v = [uint64]$x; if ($v -gt 255) { throw "bad ip $s" }; $n = $n * 256 + $v }
  return $n
}
# "a.b.c.d/nn", "a.b.c.d/255.255.0.0", "a-b", "a.b.c.d" -> start,end
function ToRange($s) {
  $s = "$s".Trim().Trim('"')
  if ($s -eq '' -or $s.Contains(':')) { return $null }
  if ($s.Contains('-')) { $a, $b = $s.Split('-'); return ,@((IpNum $a), (IpNum $b)) }
  if ($s.Contains('/')) {
    $a, $m = $s.Split('/')
    if ($m.Contains('.')) { $mask = IpNum $m; $bits = 0; while ($bits -lt 32 -and ($mask -band ([uint64]1 -shl (31 - $bits)))) { $bits++ } } else { $bits = [int]$m }
    $size = [uint64]1 -shl (32 - $bits)
    $st = (IpNum $a); $st = $st - ($st % $size)
    return ,@($st, ($st + $size - 1))
  }
  $n = IpNum $s; return ,@($n, $n)
}
function Merge($list) {
  $sorted = @($list | Where-Object { $_ } | Sort-Object { $_[0] })
  $out = New-Object 'System.Collections.Generic.List[object]'
  foreach ($r in $sorted) {
    if ($out.Count -gt 0 -and $r[0] -le $out[$out.Count - 1][1] + 1) {
      if ($r[1] -gt $out[$out.Count - 1][1]) { $out[$out.Count - 1][1] = $r[1] }
    } else { $out.Add(@($r[0], $r[1])) }
  }
  return ,$out
}
function Total($m) { $t = [double]0; foreach ($r in $m) { $t += $r[1] - $r[0] + 1 }; return $t }
function Common($a, $b) {
  $i = 0; $j = 0; $t = [double]0
  while ($i -lt $a.Count -and $j -lt $b.Count) {
    $lo = [Math]::Max($a[$i][0], $b[$j][0]); $hi = [Math]::Min($a[$i][1], $b[$j][1])
    if ($lo -le $hi) { $t += $hi - $lo + 1 }
    if ($a[$i][1] -lt $b[$j][1]) { $i++ } else { $j++ }
  }
  return $t
}

# what the firewall lets in now
$fw = $null
$rules = @(Get-NetFirewallRule -Group 'Country IP Filter' -ErrorAction SilentlyContinue | Sort-Object Name)
if ($rules.Count -gt 0) {
  $ids = @($rules | ForEach-Object { if ($_.Name -cmatch '^CountryIPFilter-(.+)-([0-9]{2,})$') { $Matches[1] } } | Sort-Object -Unique)
  $set = @($rules | Where-Object { $_.Name -cmatch ('^CountryIPFilter-' + [regex]::Escape($ids[0]) + '-[0-9]{2,}$') })
  if ($cc.Count -eq 0 -and "$($set[0].Description)" -cmatch '\[CC=([A-Z,]+)\]') { $cc = @($Matches[1].Split(',')) }
  $fw = Merge @($set | Get-NetFirewallAddressFilter | ForEach-Object { $_.RemoteAddress } | ForEach-Object { ToRange $_ })
}
if ($cc.Count -eq 0) { throw 'No countries: protection is off. Put the country code in $cc, for example $cc = @(''IR'')' }
Write-Host ("Countries: " + ($cc -join ', '))
Write-Host "Downloading, this can take a few minutes..."

$src = [ordered]@{}
# 1. RIPEstat (what the program downloads)
try {
  $all = @(); $dates = @()
  foreach ($c in $cc) {
    $d = Fetch ("https://stat.ripe.net/data/country-resource-list/data.json?v4_format=prefix&resource=" + $c) ("ripestat-$c.json")
    $j = [IO.File]::ReadAllText($d.File) | ConvertFrom-Json
    $q = $j.data.query_time
    if ($q -is [datetime]) { $dates += $q.ToString('yyyy-MM-dd') } else { $dates += "$q".Substring(0, 10) }
    $all += @($j.data.resources.ipv4 | ForEach-Object { ToRange $_ })
  }
  $src['RIPEstat (used by the program)'] = @{ M = (Merge $all); Date = (($dates | Sort-Object -Unique) -join ' ') }
} catch { $src['RIPEstat (used by the program)'] = @{ Err = "$_" } }
# 2. the five registries' own files (the original data)
try {
  $all = New-Object 'System.Collections.Generic.List[object]'; $dates = @()
  foreach ($u in @('https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest', 'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest', 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest', 'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest', 'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest')) {
    $d = Fetch $u ('rir-' + [IO.Path]::GetFileName($u))
    $first = $true
    foreach ($l in [IO.File]::ReadLines($d.File)) {
      if ($first -and $l -cmatch '^[0-9.]+\|([a-z]+)\|([0-9]{8})\|') { $dates += $Matches[1] + ' ' + $Matches[2]; $first = $false; continue }
      foreach ($c in $cc) {
        if ($l.Contains("|$c|ipv4|")) {
          $f = $l.Split('|')
          if ($f[1] -ceq $c -and $f[2] -ceq 'ipv4' -and ($f[6] -ceq 'allocated' -or $f[6] -ceq 'assigned')) { $s = IpNum $f[3]; $all.Add(@($s, ($s + [uint64]$f[4] - 1))) }
        }
      }
    }
  }
  $src['Registries (RIPE, ARIN, APNIC, LACNIC, AFRINIC)'] = @{ M = (Merge $all); Date = ('oldest ' + (@($dates | ForEach-Object { $_.Split(' ')[1] } | Sort-Object)[0] -replace '^(....)(..)(..)$', '$1-$2-$3')) }
} catch { $src['Registries (RIPE, ARIN, APNIC, LACNIC, AFRINIC)'] = @{ Err = "$_" } }
# 3. ipdeny.com
try {
  $all = @(); $dates = @()
  foreach ($c in $cc) {
    $d = Fetch ("https://www.ipdeny.com/ipblocks/data/aggregated/" + $c.ToLower() + "-aggregated.zone") ("ipdeny-$c.zone")
    $dates += $d.Date
    $all += @([IO.File]::ReadAllLines($d.File) | Where-Object { $_ -match '^[0-9]' } | ForEach-Object { ToRange $_ })
  }
  $src['ipdeny.com'] = @{ M = (Merge $all); Date = (($dates | Sort-Object -Unique) -join ' ') }
} catch { $src['ipdeny.com'] = @{ Err = "$_" } }
# 4. and 5. where the addresses are really used (location databases)
foreach ($g in @(@('DB-IP (location)', 'dbip-country-ipv4.csv'), @('GeoLite2 (location)', 'geolite2-country-ipv4.csv'))) {
  try {
    $d = Fetch ('https://github.com/sapics/ip-location-db/releases/download/latest/' + $g[1]) $g[1]
    $all = New-Object 'System.Collections.Generic.List[object]'
    foreach ($l in [IO.File]::ReadLines($d.File)) {
      $i = $l.LastIndexOf(',')
      if ($i -gt 0 -and $cc -ccontains $l.Substring($i + 1).Trim().Trim('"')) {
        $f = $l.Split(',')
        $all.Add(@((IpNum $f[0].Trim('"')), (IpNum $f[1].Trim('"'))))
      }
    }
    $src[$g[0]] = @{ M = (Merge $all); Date = $d.Date }
  } catch { $src[$g[0]] = @{ Err = "$_" } }
}

$baseName = 'Firewall rules now'
$base = $fw
if ($null -eq $base) {
  $baseName = 'RIPEstat (protection is off)'
  $base = $src['RIPEstat (used by the program)'].M
  if ($null -eq $base) { throw 'RIPEstat could not be downloaded.' }
}
$bt = Total $base
Write-Host ""
Write-Host ("Compared with: " + $baseName + "  (" + $bt.ToString('N0') + " addresses)") -ForegroundColor Cyan
Write-Host ""
$rows = foreach ($k in $src.Keys) {
  $s = $src[$k]
  if ($s.Err) { [pscustomobject]@{ Source = $k; Date = ''; Addresses = 'NOT DOWNLOADED'; Same = ''; 'Only in program' = ''; 'Only in source' = '' }; continue }
  $st = Total $s.M; $c = Common $base $s.M
  [pscustomobject]@{
    Source = $k
    Date = $s.Date
    Addresses = $st.ToString('N0')
    Same = $c.ToString('N0')
    'Only in program' = ('{0:N2} %' -f (100 * ($bt - $c) / [Math]::Max($bt, 1)))
    'Only in source' = ('{0:N2} %' -f (100 * ($st - $c) / [Math]::Max($st, 1)))
  }
}
$rows | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
foreach ($k in $src.Keys) { if ($src[$k].Err) { Write-Host ("Not downloaded: " + $k + " : " + $src[$k].Err) -ForegroundColor Yellow } }
Write-Host "Done. Copy everything above and send it." -ForegroundColor Green
} finally {
  if ((Split-Path -Leaf $tmp) -like 'ipcheck-*' -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}
}
