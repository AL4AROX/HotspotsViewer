<#
 FAKER FINDER - Hotspot / Tethering / Secondary-device detector
 Windows PowerShell 5.1 (powershell.exe) | Run as Administrator

 Usage:   powershell -ExecutionPolicy Bypass -File .\FakerFinder.ps1
 Options: -OutputPath <file.html>   -EventDays <n>   -NoOpen

 Everything is read locally. Nothing is uploaded anywhere.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [int]$EventDays = 7,
    [switch]$NoOpen
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$TotalSteps = 8

if (-not $OutputPath) {
    $OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'ConnectionSummary.html'
}

# ============================================================
#  Elevation
# ============================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and $PSCommandPath) {
    try {
        $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-OutputPath', "`"$OutputPath`"", '-EventDays', "$EventDays")
        if ($NoOpen) { $relaunch += '-NoOpen' }
        Start-Process -FilePath 'powershell.exe' -ArgumentList $relaunch -Verb RunAs -ErrorAction Stop
        exit
    } catch {
        Write-Host 'UAC cancelled - continuing without admin (limited results).' -ForegroundColor Yellow
    }
}

# ============================================================
#  Helpers
# ============================================================
$script:Findings  = New-Object System.Collections.Generic.List[object]
$script:extraRows = New-Object System.Collections.Generic.List[object]

function Write-Step([int]$n, [string]$text) {
    Write-Host ''
    Write-Host ('[{0}/{1}] {2}' -f $n, $TotalSteps, $text) -ForegroundColor Green
}

function Write-Line([string]$text, [string]$color = 'Gray') {
    Write-Host ('  ' + $text) -ForegroundColor $color
}

function Add-Finding {
    param(
        [ValidateSet('High', 'Medium', 'Info')][string]$Severity,
        [string]$Category,
        [string]$Message
    )
    $script:Findings.Add([pscustomobject]@{ Severity = $Severity; Category = $Category; Message = $Message })
    $color = 'Cyan'
    if ($Severity -eq 'High')   { $color = 'Red' }
    if ($Severity -eq 'Medium') { $color = 'Yellow' }
    Write-Host ('  [{0}] {1}' -f $Severity.ToUpper(), $Message) -ForegroundColor $color
}

function Add-Extra([string]$check, [string]$result, [string]$flag = '') {
    $script:extraRows.Add([pscustomobject]@{ Cells = @($check, $result); Flag = $flag })
}

function ConvertFrom-SystemTime([byte[]]$Bytes) {
    if (-not $Bytes -or $Bytes.Length -lt 16) { return $null }
    try {
        $y  = [int][BitConverter]::ToUInt16($Bytes, 0)
        $mo = [int][BitConverter]::ToUInt16($Bytes, 2)
        $d  = [int][BitConverter]::ToUInt16($Bytes, 6)
        $h  = [int][BitConverter]::ToUInt16($Bytes, 8)
        $mi = [int][BitConverter]::ToUInt16($Bytes, 10)
        $s  = [int][BitConverter]::ToUInt16($Bytes, 12)
        return [datetime]::new($y, $mo, $d, $h, $mi, $s)
    } catch { return $null }
}

function Get-ProfileType([int]$code) {
    switch ($code) {
        71      { 'Wireless' }
        6       { 'Wired' }
        23      { 'VPN / Broadband' }
        243     { 'Mobile Broadband' }
        default { "Other ($code)" }
    }
}

function Get-AdapterClass([string]$desc) {
    if     ($desc -match 'Hosted Network Virtual') { 'Hosted Network' }
    elseif ($desc -match 'Wi-Fi Direct')           { 'Wi-Fi Direct / Hotspot' }
    elseif ($desc -match 'RNDIS|Remote NDIS|Apple Mobile Device Ethernet|Android|Samsung Mobile|Tethering|Mobile Broadband') { 'USB / Phone tethering' }
    elseif ($desc -match 'Bluetooth')              { 'Bluetooth PAN' }
    elseif ($desc -match 'VMware|VirtualBox|Hyper-V|vEthernet|TAP-|Npcap|WireGuard|OpenVPN|Tailscale|ZeroTier|Virtual') { 'Virtual / VM / VPN' }
    else   { 'Physical / Other' }
}

function Format-Date($d) {
    if ($d) { return $d.ToString('yyyy-MM-dd HH:mm') }
    return '-'
}

# ============================================================
#  Banner
# ============================================================
$Host.UI.RawUI.WindowTitle = 'Faker Finder'
Clear-Host
$banner = @'
 _____     _     _  __ _____  ____
|  ___|   / \   | |/ /| ____||  _ \
| |_     / _ \  | ' / |  _|  | |_) |
|  _|   / ___ \ | . \ | |___ |  _ <
|_|    /_/   \_\|_|\_\|_____||_| \_\
'@
Write-Host $banner -ForegroundColor Green
Write-Host ''
Write-Host 'Searching for Fakers!' -ForegroundColor Green
Write-Host ''
Write-Host 'Hotspot Detections for Fakers' -ForegroundColor Cyan
Write-Host 'Hotspot / tethering / secondary-device checks' -ForegroundColor Cyan
if (-not $isAdmin) { Write-Host 'WARNING: not running as Administrator - some checks may be incomplete.' -ForegroundColor Yellow }

# ============================================================
#  [1/8] System info
# ============================================================
Write-Step 1 'Collecting system information...'
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$boot = $os.LastBootUpTime
$bootText = '-'
$uptimeText = '-'
if ($boot) {
    $bootText = $boot.ToString('yyyy-MM-dd HH:mm:ss')
    $up = (Get-Date) - $boot
    $uptimeText = '{0}d {1}h {2}m' -f $up.Days, $up.Hours, $up.Minutes
}
$osText = ('{0} (build {1})' -f $os.Caption, $os.BuildNumber)
Write-Line ('Computer : ' + $env:COMPUTERNAME)
Write-Line ('Windows  : ' + $osText)
Write-Line ('Uptime   : ' + $uptimeText)

# ============================================================
#  [2/8] Hosted Network (netsh)
# ============================================================
Write-Step 2 'Checking Hosted Network...'
$hostedRaw = (netsh wlan show hostednetwork 2>&1 | Out-String)
$hosted = [ordered]@{ Active = $false; SSID = ''; Clients = 0 }
if ($hostedRaw -match '(?im)^\s*(Status|Estado)\s*:\s*(Started|Iniciad[oa])\s*$') { $hosted.Active = $true }
if ($hostedRaw -match '(?im)^\s*SSID[^:\r\n]*:\s*"?(.*?)"?\s*$')                  { $hosted.SSID = $Matches[1] }
if ($hostedRaw -match '(?im)^\s*(Number of clients|N.mero de clientes)\s*:\s*(\d+)') { $hosted.Clients = [int]$Matches[2] }
if ($hosted.Active) {
    Add-Finding High 'Hosted Network' ('Hosted Network is STARTED (SSID: {0}, clients: {1})' -f $hosted.SSID, $hosted.Clients)
} else {
    Write-Line 'Hosted Network: Inactive' Green
}

# ============================================================
#  [3/8] Mobile Hotspot service + tethering state
# ============================================================
Write-Step 3 'Checking Mobile Hotspot service and tethering state...'
$svc = Get-Service -Name 'icssvc'
$svcState = 'Not present'
if ($svc) { $svcState = $svc.Status.ToString() }
$mobile = [ordered]@{ Service = $svcState; Tethering = 'Unknown'; Clients = 0; Profile = ''; ClientList = @() }

# WinRT tethering manager (works in Windows PowerShell 5.1, not in PowerShell 7)
try {
    $null = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
    $null = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
    $inetProfile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
    if ($inetProfile) {
        $mobile.Profile = $inetProfile.ProfileName
        $mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($inetProfile)
        if ($mgr) {
            $mobile.Tethering = $mgr.TetheringOperationalState.ToString()
            $mobile.Clients   = [int]$mgr.ClientCount
            foreach ($c in $mgr.GetTetheringClients()) {
                $names = ($c.HostNames | ForEach-Object { $_.DisplayName }) -join ', '
                $mobile.ClientList += [pscustomobject]@{ MAC = "$($c.MacAddress)"; Host = $names }
            }
        }
    }
} catch { }

$mobileActive = ($mobile.Service -eq 'Running') -or ($mobile.Tethering -eq 'On')
if ($mobile.Service -eq 'Running') { Add-Finding High 'Mobile Hotspot' 'Windows Mobile Hotspot Service (icssvc) is RUNNING' }
if ($mobile.Tethering -eq 'On')    { Add-Finding High 'Mobile Hotspot' ('Mobile Hotspot is ON (connected clients: {0})' -f $mobile.Clients) }
elseif ($mobile.Clients -gt 0)     { Add-Finding High 'Mobile Hotspot' ('Mobile Hotspot reports {0} connected client(s)' -f $mobile.Clients) }
if (-not $mobileActive) { Write-Line 'Mobile Hotspot: Stopped' Green }

# ============================================================
#  [4/8] Saved / current network profiles
# ============================================================
Write-Step 4 'Analyzing network profiles...'
$hotspotRegex   = "(?i)(iphone|ipad|galaxy|samsung|android|redmi|xiaomi|poco|oppo|realme|oneplus|huawei|honor|pixel|motorola|tecno|infinix|hotspot|tether|^DIRECT-|^mi[ -]?\d+|'s (phone|galaxy|iphone))"
$pcRegex        = '^' + [regex]::Escape($env:COMPUTERNAME) + '([ _-]?\d{1,4})?$'
$winDefaultRegex = '^(DESKTOP|LAPTOP)-[A-Z0-9]{5,8} \d{3,4}$'
$profRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
$profiles = @()
foreach ($k in @(Get-ChildItem $profRoot)) {
    $p = Get-ItemProperty -Path $k.PSPath
    if (-not $p) { continue }
    $name    = "$($p.ProfileName)"
    $type    = Get-ProfileType ([int]$p.NameType)
    $created = ConvertFrom-SystemTime $p.DateCreated
    $last    = ConvertFrom-SystemTime $p.DateLastConnected
    $reason  = ''
    if ($type -eq 'Wireless') {
        if     ($name -match $pcRegex)         { $reason = 'Name matches this PC (Windows hotspot default)' }
        elseif ($name -match $winDefaultRegex) { $reason = 'Windows PC hotspot default name' }
        elseif ($name -match $hotspotRegex)    { $reason = 'Phone / hotspot-like name' }
    }
    if ($reason) {
        $recent = ($null -ne $last) -and (((Get-Date) - $last).TotalHours -lt 24)
        $sev = 'Medium'
        if ($recent) { $sev = 'High' }
        Add-Finding $sev 'Network Profile' ("Hotspot-like profile '{0}' - {1} - last connected {2}" -f $name, $reason, (Format-Date $last))
    }
    $profiles += [pscustomobject]@{ SSID = $name; Type = $type; Created = $created; LastConnected = $last; Reason = $reason }
}
$profiles = @($profiles | Sort-Object @{ Expression = { if ($_.LastConnected) { $_.LastConnected } else { [datetime]::MinValue } }; Descending = $true })
$hotspotProfileCount = @($profiles | Where-Object { $_.Reason }).Count

# Currently connected networks
$currentNames = @()
foreach ($cp in @(Get-NetConnectionProfile)) {
    $currentNames += "$($cp.Name) [$($cp.InterfaceAlias)]"
    if ("$($cp.Name)" -match $hotspotRegex -or "$($cp.Name)" -match $winDefaultRegex -or "$($cp.Name)" -match $pcRegex) {
        Add-Finding High 'Current Connection' ("Currently connected to a hotspot-like network: '{0}' on {1}" -f $cp.Name, $cp.InterfaceAlias)
    }
}
$wlanRaw = (netsh wlan show interfaces 2>&1 | Out-String)
$currentSsid = ''
if ($wlanRaw -match '(?im)^\s*SSID\s*:\s*(.+?)\s*$') { $currentSsid = $Matches[1] }
if ($currentSsid -and ($currentSsid -match $hotspotRegex -or $currentSsid -match $winDefaultRegex)) {
    Add-Finding High 'Current Connection' ("Wi-Fi SSID in use looks like a hotspot: '{0}'" -f $currentSsid)
}
Write-Line ('Profiles found: {0} | Hotspot-like: {1}' -f $profiles.Count, $hotspotProfileCount) $(if ($hotspotProfileCount -gt 0) { 'Yellow' } else { 'Green' })

# ============================================================
#  [5/8] Network adapters
# ============================================================
Write-Step 5 'Inspecting network adapters (virtual / tethering / Wi-Fi Direct)...'
$adapterRows = @()
$virtUp = 0
$vmUp = @()
foreach ($a in @(Get-NetAdapter | Sort-Object @{ Expression = { "$($_.Status)" -ne 'Up' } }, Name)) {
    $desc  = "$($a.InterfaceDescription)"
    $class = Get-AdapterClass $desc
    $isUp  = ("$($a.Status)" -eq 'Up')
    $flag  = ''
    if ($isUp) {
        switch ($class) {
            'Hosted Network'         { $flag = 'bad';  $virtUp++; Add-Finding High   'Adapters' ('Hosted Network adapter is UP: {0} ({1})' -f $a.Name, $desc) }
            'Wi-Fi Direct / Hotspot' { $flag = 'bad';  $virtUp++; Add-Finding High   'Adapters' ('Wi-Fi Direct / hotspot virtual adapter is UP: {0} ({1})' -f $a.Name, $desc) }
            'USB / Phone tethering'  { $flag = 'bad';  $virtUp++; Add-Finding High   'Adapters' ('USB / phone tethering adapter is UP: {0} ({1})' -f $a.Name, $desc) }
            'Bluetooth PAN'          { $flag = 'warn'; $virtUp++; Add-Finding Medium 'Adapters' ('Bluetooth network adapter is UP: {0} ({1})' -f $a.Name, $desc) }
            'Virtual / VM / VPN'     { $flag = 'warn'; $vmUp += $a.Name }
        }
    }
    $adapterRows += [pscustomobject]@{ Cells = @($a.Name, $desc, "$($a.Status)", "$($a.MacAddress)", $class); Flag = $flag }
}
if ($vmUp.Count -gt 0) {
    Add-Finding Info 'Adapters' ('Virtual / VM / VPN adapters are UP: ' + ($vmUp -join ', '))
}
if ($virtUp -eq 0) { Write-Line 'No hotspot-related virtual adapters are up' Green }

# ============================================================
#  [6/8] Connected devices (ARP / neighbors) + gateways
# ============================================================
Write-Step 6 'Scanning connected devices and gateways...'
$gwMap = @{
    '172.20.10.1'    = 'iPhone Personal Hotspot gateway'
    '192.168.43.1'   = 'Android hotspot gateway'
    '192.168.42.129' = 'Android USB tethering gateway'
    '192.168.49.1'   = 'Wi-Fi Direct group owner (Android)'
    '192.168.137.1'  = 'Windows ICS / Mobile Hotspot gateway'
}
$gwRows = @()
foreach ($cfg in @(Get-NetIPConfiguration)) {
    $gw     = "$(@($cfg.IPv4DefaultGateway.NextHop)[0])"
    $myIps  = @($cfg.IPv4Address | ForEach-Object { $_.IPAddress })
    $label  = ''
    if ($gw -and $gwMap.ContainsKey($gw)) {
        $label = 'Connected THROUGH: ' + $gwMap[$gw]
        Add-Finding High 'Gateway' ("Default gateway {0} on '{1}' = {2}" -f $gw, $cfg.InterfaceAlias, $gwMap[$gw])
    }
    foreach ($ip in $myIps) {
        if ($ip -and $gwMap.ContainsKey($ip)) {
            $label = 'This PC is HOSTING: ' + $gwMap[$ip]
            Add-Finding High 'Gateway' ("This PC holds {0} on '{1}' = {2}" -f $ip, $cfg.InterfaceAlias, $gwMap[$ip])
        }
    }
    $flag = ''
    if ($label) { $flag = 'bad' }
    $gwRows += [pscustomobject]@{ Cells = @("$($cfg.InterfaceAlias)", ($myIps -join ', '), $gw, $label); Flag = $flag }
}

$ownIps = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "$($_.IPAddress)" })
$seen = @{}
$deviceRows = @()
$deviceCount = 0
$randomMacCount = 0
foreach ($n in @(Get-NetNeighbor -AddressFamily IPv4 | Sort-Object { [version]$_.IPAddress })) {
    $state = "$($n.State)"
    $mac   = "$($n.LinkLayerAddress)"
    $ip    = "$($n.IPAddress)"
    if (-not $mac)                                                       { continue }
    if ($mac -match '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$')          { continue }
    if ($mac -match '^01-00-5E')                                         { continue }
    if ($state -notin 'Reachable', 'Stale', 'Permanent', 'Delay', 'Probe') { continue }
    if ($ip -match '^(22[4-9]|23\d|255)\.' -or $ip -match '\.255$' -or $ip -match '^169\.254\.') { continue }
    if ($ownIps -contains $ip)                                           { continue }
    $key = "$ip|$mac"
    if ($seen[$key]) { continue }
    $seen[$key] = $true

    $notes = @()
    $flag  = ''
    if ($ip -match '^192\.168\.137\.' -and $ip -ne '192.168.137.1') {
        $notes += 'Client on the Windows hotspot / ICS subnet'
        $flag = 'bad'
        Add-Finding High 'Connected Devices' ('Device {0} ({1}) is on the Windows hotspot / ICS subnet (192.168.137.x)' -f $ip, $mac)
    }
    if ($gwMap.ContainsKey($ip)) { $notes += $gwMap[$ip]; $flag = 'bad' }
    if ($mac -match '^[0-9A-F][26AE]-') { $notes += 'Randomized (private) MAC - typical of phones'; $randomMacCount++ ; if (-not $flag) { $flag = 'warn' } }
    $deviceCount++
    $deviceRows += [pscustomobject]@{ Cells = @($ip, $mac.ToLower(), "$($n.InterfaceAlias)", $state, ($notes -join '; ')); Flag = $flag }
}
Write-Line ('Connected devices: {0} | randomized MACs: {1}' -f $deviceCount, $randomMacCount)
if ($deviceCount -gt 1) { Write-Line 'Note: Multiple devices detected - review the Connected Devices table' Yellow }

# Tethering clients reported by Windows
foreach ($tc in $mobile.ClientList) {
    Add-Finding High 'Mobile Hotspot' ('Tethering client connected: {0} {1}' -f $tc.MAC, $tc.Host)
}

# ============================================================
#  [7/8] Extra checks
# ============================================================
Write-Step 7 'Running extra checks (ICS, event log, remote tools, VM)...'

# -- Internet Connection Sharing
$ics = Get-Service -Name 'SharedAccess'
$icsState = 'Not present'
if ($ics) { $icsState = $ics.Status.ToString() }
$icsFlag = ''
if ($icsState -eq 'Running') {
    $icsFlag = 'warn'
    Add-Finding Info 'ICS' 'Internet Connection Sharing service is running (can also come from Hyper-V / WSL / Docker)'
}
Add-Extra 'Internet Connection Sharing service (SharedAccess)' $icsState $icsFlag

# -- Event log: hotspot / ICS service activity
$since = (Get-Date).AddDays(-[math]::Abs($EventDays))
$hotspotEvtRegex = 'Mobile Hotspot|cobertura inal|Zona con cobertura'
$icsEvtRegex     = 'Internet Connection Sharing|Conexi.n compartida'
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7036; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $hotspotEvtRegex -or $_.Message -match $icsEvtRegex } |
    Select-Object -First 15)
$hsEvents = @($events | Where-Object { $_.Message -match $hotspotEvtRegex })
if ($hsEvents.Count -gt 0) {
    $latest = $hsEvents[0].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    Add-Finding Medium 'Event Log' ('Mobile Hotspot service changed state {0} time(s) in the last {1} day(s) - latest {2}' -f $hsEvents.Count, $EventDays, $latest)
}
$eventRows = @()
foreach ($ev in $events) {
    $msg = ($ev.Message -split "`r?`n")[0]
    $flag = ''
    if ($ev.Message -match $hotspotEvtRegex) { $flag = 'warn' }
    $eventRows += [pscustomobject]@{ Cells = @($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $msg); Flag = $flag }
}

# -- Remote access tools
$remoteRegex = '^(AnyDesk|TeamViewer.*|rustdesk|parsecd?|chrome_remote_desktop.*|remoting_host|UltraViewer.*|winvnc|vncserver|tvnserver|uvnc_service|Splashtop.*|SRService|sunshine|moonlight|nxserver|nomachine|LogMeIn.*|ammyy.*|Supremo.*|radmin|rutserv|rfusclient|ToDesk.*|SunloginClient|msra|QuickAssist|ScreenConnect.*|meshagent|dwagent|HopToDesk)$'
$remote = @(Get-Process | Where-Object { $_.ProcessName -match $remoteRegex } | Select-Object -ExpandProperty ProcessName -Unique)
if ($remote.Count -gt 0) {
    Add-Finding Medium 'Remote Tools' ('Remote-access tool(s) running: ' + ($remote -join ', '))
    Add-Extra 'Remote-access tools running' ($remote -join ', ') 'warn'
} else {
    Add-Extra 'Remote-access tools running' 'None' ''
}
if (Get-Process -Name 'mstsc') { Add-Finding Info 'Remote Tools' 'Remote Desktop client (mstsc) is open'; Add-Extra 'RDP client (mstsc)' 'Open' 'warn' }

# -- Incoming RDP
$rdpEnabled  = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0)
$rdpSessions = @(Get-NetTCPConnection -LocalPort 3389 -State Established)
if ($rdpSessions.Count -gt 0) {
    Add-Finding High 'RDP' ('Active incoming RDP session(s): ' + (($rdpSessions | ForEach-Object { $_.RemoteAddress }) -join ', '))
    Add-Extra 'Incoming RDP session' (($rdpSessions | ForEach-Object { $_.RemoteAddress }) -join ', ') 'bad'
} elseif ($rdpEnabled) {
    Add-Finding Info 'RDP' 'Remote Desktop is enabled on this PC (no active session)'
    Add-Extra 'Remote Desktop (incoming)' 'Enabled, no active session' 'warn'
} else {
    Add-Extra 'Remote Desktop (incoming)' 'Disabled' ''
}

# -- Virtual machine
$vmRegex = 'virtual|vmware|virtualbox|vbox|kvm|qemu|xen|hyper-v|parallels|bochs|bhyve'
$hwText  = ('{0} | {1} | {2} | {3}' -f $cs.Manufacturer, $cs.Model, $bios.Manufacturer, $bios.SMBIOSBIOSVersion)
if ($hwText -match $vmRegex) {
    Add-Finding Medium 'Virtual Machine' ('System looks like a virtual machine: ' + $hwText)
    Add-Extra 'Running inside a virtual machine' ('YES - ' + $hwText) 'bad'
} else {
    Add-Extra 'Running inside a virtual machine' ('No - ' + $hwText) ''
}

Add-Extra 'Last boot / uptime' ("$bootText  ($uptimeText)") ''
Add-Extra 'Currently connected networks' ($(if ($currentNames.Count) { $currentNames -join ', ' } else { 'None' })) ''
if ($currentSsid) { Add-Extra 'Current Wi-Fi SSID' $currentSsid '' }
Write-Line 'Extra checks done' Green

# ============================================================
#  [8/8] HTML report
# ============================================================
Write-Step 8 'Generating HTML Report...'

function Esc([object]$s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
function New-Box([string]$text, [string]$cls) { '<div class="box ' + $cls + '">' + (Esc $text) + '</div>' }

function ConvertTo-HtmlTable {
    param([string[]]$Headers, [object[]]$Rows, [string]$Empty = 'Nothing found')
    $t = New-Object System.Text.StringBuilder
    [void]$t.Append('<table><thead><tr>')
    foreach ($h in $Headers) { [void]$t.Append('<th>' + (Esc $h) + '</th>') }
    [void]$t.AppendLine('</tr></thead><tbody>')
    if (-not $Rows -or $Rows.Count -eq 0) {
        [void]$t.AppendLine('<tr><td colspan="' + $Headers.Count + '" class="empty">' + (Esc $Empty) + '</td></tr>')
    } else {
        foreach ($r in $Rows) {
            $cls = ''
            if ($r.Flag) { $cls = ' class="' + $r.Flag + '"' }
            [void]$t.Append('<tr' + $cls + '>')
            foreach ($c in $r.Cells) { [void]$t.Append('<td>' + (Esc $c) + '</td>') }
            [void]$t.AppendLine('</tr>')
        }
    }
    [void]$t.AppendLine('</tbody></table>')
    $t.ToString()
}

$high   = @($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count
$medium = @($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
$suspicious = $high + $medium

if     ($high -gt 0)   { $vTitle = 'SUSPICIOUS'; $vCls = 'bad';  $vText = "$high high-severity indicator(s) of hotspot / tethering / secondary-device usage were found." }
elseif ($medium -gt 0) { $vTitle = 'REVIEW';     $vCls = 'warn'; $vText = "$medium medium-severity indicator(s) need a manual review." }
else                   { $vTitle = 'CLEAN';      $vCls = 'ok';   $vText = 'No hotspot or tethering evidence was found.' }

$css = @'
body{font-family:"Segoe UI",Arial,sans-serif;background:#f5f6f8;color:#2d3a4a;margin:0;padding:28px 40px 50px}
h1{margin:0 0 6px;font-size:32px}
h2{margin:32px 0 10px;font-size:23px}
.meta{font-size:14px;color:#44505e;line-height:1.7}
.box{padding:14px 16px;border-radius:6px;color:#fff;font-size:15px;margin-bottom:8px}
.ok{background:#2eb25c}.bad{background:#d63c3c}.warn{background:#d99a06}.info{background:#3b82c4}
table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.15);margin-bottom:8px}
th{background:#2f4157;color:#fff;text-align:left;padding:11px 12px;font-size:15px}
td{padding:9px 12px;border-bottom:1px solid #e3e7ec;font-size:14px;word-break:break-word}
td.empty{color:#7a8794;font-style:italic}
tr.bad td{background:#fdeaea}tr.warn td{background:#fff6dd}
.verdict{font-size:22px;font-weight:600}
.small{font-size:12.5px;color:#6b7785;margin-top:30px;line-height:1.6}
'@

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>WiFi Analysis Report</title><style>')
[void]$sb.AppendLine($css)
[void]$sb.AppendLine('</style></head><body>')
[void]$sb.AppendLine('<h1>Hotspot detections for Fakers</h1>')
[void]$sb.AppendLine('<div class="meta">Generated: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') +
    '<br>Computer: ' + (Esc $env:COMPUTERNAME) + ' &nbsp;|&nbsp; User: ' + (Esc "$env:USERDOMAIN\$env:USERNAME") +
    ' &nbsp;|&nbsp; Admin: ' + $isAdmin +
    '<br>' + (Esc $osText) + '<br>Last boot: ' + (Esc $bootText) + ' (uptime ' + (Esc $uptimeText) + ')</div>')

# Verdict
[void]$sb.AppendLine('<h2>Verdict</h2>')
[void]$sb.AppendLine('<div class="box ' + $vCls + '"><span class="verdict">' + (Esc $vTitle) + '</span><br>' + (Esc $vText) + '</div>')

# Suspicious activities
[void]$sb.AppendLine('<h2>Suspicious Activities</h2>')
$sus = @($script:Findings | Where-Object { $_.Severity -ne 'Info' })
if ($sus.Count -eq 0) {
    [void]$sb.AppendLine((New-Box 'No suspicious activities detected' 'ok'))
} else {
    foreach ($f in $sus) {
        $cls = 'warn'
        if ($f.Severity -eq 'High') { $cls = 'bad' }
        [void]$sb.AppendLine((New-Box ('[{0}] {1}: {2}' -f $f.Severity.ToUpper(), $f.Category, $f.Message) $cls))
    }
}
$infos = @($script:Findings | Where-Object { $_.Severity -eq 'Info' })
if ($infos.Count -gt 0) {
    [void]$sb.AppendLine('<h2>Notices</h2>')
    foreach ($f in $infos) { [void]$sb.AppendLine((New-Box ('{0}: {1}' -f $f.Category, $f.Message) 'info')) }
}

# Hosted network
[void]$sb.AppendLine('<h2>Hosted Network Status</h2>')
if ($hosted.Active) { [void]$sb.AppendLine((New-Box ('ACTIVE - SSID: {0} - clients: {1}' -f $hosted.SSID, $hosted.Clients) 'bad')) }
else                { [void]$sb.AppendLine((New-Box 'Inactive' 'ok')) }

# Mobile hotspot
[void]$sb.AppendLine('<h2>Mobile Hotspot Service</h2>')
if ($mobile.Service -eq 'Running') { [void]$sb.AppendLine((New-Box 'Running' 'bad')) } else { [void]$sb.AppendLine((New-Box $(if ($mobile.Service -eq 'Stopped') { 'Stopped' } else { $mobile.Service }) 'ok')) }
if ($mobile.Tethering -eq 'On') {
    [void]$sb.AppendLine((New-Box ('Tethering: ON - clients: {0} - profile: {1}' -f $mobile.Clients, $mobile.Profile) 'bad'))
} else {
    [void]$sb.AppendLine((New-Box ('Tethering state: {0}' -f $mobile.Tethering) 'ok'))
}
if ($mobile.ClientList.Count -gt 0) {
    $tcRows = @($mobile.ClientList | ForEach-Object { [pscustomobject]@{ Cells = @($_.MAC, $_.Host); Flag = 'bad' } })
    [void]$sb.AppendLine((ConvertTo-HtmlTable -Headers @('Tethering client MAC', 'Host name') -Rows $tcRows))
}

# Profiles
[void]$sb.AppendLine('<h2>Network Profiles</h2>')
$profRows = @($profiles | ForEach-Object {
    $fl = ''
    if ($_.Reason) { $fl = 'warn' }
    [pscustomobject]@{ Cells = @($_.SSID, $_.Type, (Format-Date $_.Created), (Format-Date $_.LastConnected), $_.Reason); Flag = $fl }
})
[void]$sb.AppendLine((ConvertTo-HtmlTable -Headers @('SSID', 'Type', 'First connected', 'Last connected', 'Flag') -Rows $profRows -Empty 'No saved profiles'))

# Adapters
[void]$sb.AppendLine('<h2>Network Adapters</h2>')
[void]$sb.AppendLine((ConvertTo-HtmlTable -Headers @('Name', 'Description', 'Status', 'MAC', 'Class') -Rows $adapterRows -Empty 'No adapters found'))

# Gateways
[void]$sb.AppendLine('<h2>Gateways</h2>')
[void]$sb.AppendLine((ConvertTo-HtmlTable -Headers @('Interface', 'Local IP', 'Default gateway', 'Result') -Rows $gwRows -Empty 'No active IPv4 configuration'))

# Devices
[void]$sb.AppendLine('<h2>Connected Devices</h2>')
[void]$sb.AppendLine((ConvertTo-HtmlTable -Headers @('IP Address', 'MAC Address', 'Interface', 'State', 'Notes') -Rows $deviceRows -Empty 'No devices in the ARP table'))

# Extras
[void]$sb.AppendLine('<h2>Extra Checks</h2>')
[void]$sb.AppendLine((ConvertTo-HtmlTable -Headers @('Check', 'Result') -Rows @($script:extraRows) -Empty 'No data'))

[void]$sb.AppendLine('<h2>Hotspot / ICS service events (last ' + $EventDays + ' days)</h2>')
[void]$sb.AppendLine((ConvertTo-HtmlTable -Headers @('Time', 'Event') -Rows $eventRows -Empty 'No hotspot / ICS service events found'))

[void]$sb.AppendLine('<div class="small">This report lists indicators only. A clean result is not proof that no second device is used, and a flagged item is not proof of cheating: review each entry manually. Generated locally, nothing is uploaded.</div>')
[void]$sb.AppendLine('</body></html>')

$reportOk = $false
try {
    $dir = Split-Path $OutputPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
} catch { }
if (Test-Path $OutputPath) { $reportOk = $true; Write-Line 'Report saved successfully' Green }
else { Write-Line 'Could not save the report (check -OutputPath)' Red }

# ============================================================
#  Console summary
# ============================================================
function Write-Kv([string]$key, [string]$value, [bool]$bad) {
    $color = 'Green'
    if ($bad) { $color = 'Red' }
    Write-Host ('  ' + $key + ': ') -NoNewline -ForegroundColor Cyan
    Write-Host $value -ForegroundColor $color
}

Write-Host ''
Write-Host 'SUMMARY:' -ForegroundColor Cyan
Write-Kv 'Suspicious Activities' "$suspicious" ($suspicious -gt 0)
Write-Kv 'Hotspot Profiles'      "$hotspotProfileCount" ($hotspotProfileCount -gt 0)
Write-Kv 'Hosted Network'        $(if ($hosted.Active) { 'ACTIVE' } else { 'Inactive' }) $hosted.Active
Write-Kv 'Mobile Hotspot'        $(if ($mobileActive) { 'RUNNING' } else { 'Stopped' }) $mobileActive
Write-Kv 'Virtual Adapters'      "$virtUp" ($virtUp -gt 0)
Write-Kv 'Connected Devices'     "$deviceCount" $false
Write-Kv 'Remote Tools'          "$($remote.Count)" ($remote.Count -gt 0)
Write-Kv 'Verdict'               $vTitle ($vTitle -ne 'CLEAN')
Write-Host ''
Write-Host ('Report Location: ' + $OutputPath) -ForegroundColor Green

if ($reportOk -and -not $NoOpen) {
    Write-Host ''
    Write-Host 'Opening report in browser...' -ForegroundColor Green
    Start-Process $OutputPath
}

Write-Host ''
Write-Host 'Script complete. Press any key to exit...' -ForegroundColor Green
try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { Read-Host | Out-Null }
