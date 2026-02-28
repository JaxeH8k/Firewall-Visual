#Requires -Modules GroupPolicy, NetSecurity
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Creates a GPO containing 300 random inbound firewall rules applied to all profiles.
.PARAMETER GPOName
    Name of the GPO to create. Defaults to "Inbound_Firewall_Test_GPO".
.PARAMETER Domain
    Target AD domain. Defaults to the current machine's domain.
.PARAMETER LinkOU
    Optional Distinguished Name of an OU to link the GPO to after creation.
    Example: "OU=Computers,DC=corp,DC=local"
.PARAMETER RuleCount
    Number of rules to generate. Defaults to 300.
.EXAMPLE
    .\New-RandomFirewallGPO.ps1
.EXAMPLE
    .\New-RandomFirewallGPO.ps1 -GPOName "TestFW_GPO" -LinkOU "OU=TestComputers,DC=corp,DC=local"
#>

param(
    [string]$GPOName   = "Inbound_Firewall_Test_GPO",
    [string]$Domain    = $env:USERDNSDOMAIN,
    [string]$LinkOU    = $null,
    [int]   $RuleCount = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Import-Module GroupPolicy -ErrorAction Stop

# ─── Create / Recreate GPO ────────────────────────────────────────────────────

Write-Host "[*] Creating GPO '$GPOName' in domain '$Domain'..." -ForegroundColor Cyan

$existingGPO = Get-GPO -Name $GPOName -Domain $Domain -ErrorAction SilentlyContinue
if ($existingGPO) {
    Write-Warning "GPO '$GPOName' already exists — removing and recreating."
    Remove-GPO -Name $GPOName -Domain $Domain
}

$GPO = New-GPO -Name $GPOName -Domain $Domain `
               -Comment "Auto-generated GPO with $RuleCount random inbound firewall rules"
Write-Host "[+] GPO created  |  DisplayName: $($GPO.DisplayName)  |  ID: $($GPO.Id)" -ForegroundColor Green

# ─── Open GPO firewall policy session ────────────────────────────────────────

Write-Host "[*] Opening GPO firewall session..." -ForegroundColor Cyan
$GPOSession = Open-NetGPO -PolicyStore "$Domain\$GPOName"

# ─── Randomisation pools ──────────────────────────────────────────────────────

$protocols = @('TCP', 'UDP', 'ICMPv4', 'ICMPv6', 'Any')

$actions = @('Allow', 'Block')

$programs = @(
    'Any',
    '%SystemRoot%\System32\svchost.exe',
    '%SystemRoot%\System32\lsass.exe',
    '%SystemRoot%\System32\msiexec.exe',
    '%SystemRoot%\explorer.exe',
    '%SystemRoot%\System32\cmd.exe',
    '%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe',
    '%SystemRoot%\System32\wbem\wmiprvse.exe',
    '%SystemRoot%\System32\services.exe',
    '%SystemRoot%\System32\spoolsv.exe',
    '%SystemRoot%\System32\mmc.exe',
    '%SystemRoot%\System32\wscript.exe',
    '%SystemRoot%\System32\cscript.exe',
    '%SystemRoot%\System32\net.exe',
    '%SystemRoot%\System32\rundll32.exe',
    '%SystemRoot%\System32\taskhost.exe',
    '%ProgramFiles%\Internet Explorer\iexplore.exe',
    '%ProgramFiles%\Microsoft Office\root\Office16\WINWORD.EXE',
    '%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE',
    '%ProgramFiles%\Microsoft Office\root\Office16\OUTLOOK.EXE',
    '%ProgramFiles%\Google\Chrome\Application\chrome.exe',
    '%ProgramFiles%\Mozilla Firefox\firefox.exe',
    '%ProgramFiles%\7-Zip\7z.exe',
    '%ProgramFiles%\Notepad++\notepad++.exe',
    '%ProgramFiles%\PuTTY\putty.exe'
)

$remoteAddresses = @(
    'Any',
    'LocalSubnet',
    'DNS',
    'DHCP',
    'WINS',
    'DefaultGateway',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '192.168.1.0/24',
    '10.10.0.0/16',
    '10.20.30.0/24',
    '203.0.113.0/24',
    '198.51.100.0/24'
)

$localAddresses = @(
    'Any',
    'LocalSubnet',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '192.168.1.0/24'
)

$edgeTraversalPolicies = @('Block', 'Allow', 'DeferToApp', 'DeferToUser')

$interfaceTypes = @('Any', 'Wired', 'Wireless', 'RemoteAccess')

$services = @(
    'Any', 'W32Time', 'WinRM', 'BITS', 'Spooler',
    'Winmgmt', 'EventLog', 'Schedule', 'Dnscache',
    'LanmanServer', 'LanmanWorkstation', 'TermService'
)

$enabledStates = @('True', 'False')

# Common well-known ports used as anchors when randomising
$wellKnownPorts = @(21,22,23,25,53,80,110,135,139,143,389,443,445,
                    636,1433,1521,3306,3389,5985,5986,8080,8443,9000)

# ─── Helper: pick a random port expression ───────────────────────────────────

function Get-RandomPort {
    $mode = Get-Random -Minimum 0 -Maximum 5
    switch ($mode) {
        0 { return (Get-Random -Minimum 1    -Maximum 65535).ToString() }                      # single random
        1 { return ($wellKnownPorts | Get-Random).ToString() }                                 # well-known
        2 { # range
            $s = Get-Random -Minimum 1 -Maximum 60000
            $e = [Math]::Min($s + (Get-Random -Minimum 10 -Maximum 5000), 65535)
            return "$s-$e"
        }
        3 { # comma list
            $p1 = Get-Random -Minimum 1 -Maximum 65535
            $p2 = Get-Random -Minimum 1 -Maximum 65535
            return "$p1,$p2"
        }
        default { return 'Any' }
    }
}

# ─── Generate rules ───────────────────────────────────────────────────────────

Write-Host "[*] Generating $RuleCount random inbound firewall rules..." -ForegroundColor Cyan
$successCount = 0
$failCount    = 0

for ($i = 1; $i -le $RuleCount; $i++) {

    $protocol   = $protocols             | Get-Random
    $action     = $actions               | Get-Random
    $program    = $programs              | Get-Random
    $edgePol    = $edgeTraversalPolicies | Get-Random
    $ifaceType  = $interfaceTypes        | Get-Random
    $remoteAddr = $remoteAddresses       | Get-Random
    $localAddr  = $localAddresses        | Get-Random
    $service    = $services              | Get-Random
    $enabled    = $enabledStates         | Get-Random

    # Unique rule name  (e.g. "RndInbound_042_a3f9c811")
    $ruleName = "RndInbound_{0:D3}_{1}" -f $i, [System.Guid]::NewGuid().ToString('N').Substring(0,8)

    # ── Core parameters ──────────────────────────────────────────────────────
    $ruleParams = @{
        GPOSession          = $GPOSession
        Name                = $ruleName
        DisplayName         = $ruleName
        Description         = "Auto-generated rule #$i | Protocol: $protocol | Action: $action | Interface: $ifaceType"
        Direction           = 'Inbound'
        Action              = $action
        Protocol            = $protocol
        Profile             = 'Any'          # applies to Domain, Private AND Public
        Enabled             = $enabled
        EdgeTraversalPolicy = $edgePol
        InterfaceType       = $ifaceType
    }

    # ── Program ──────────────────────────────────────────────────────────────
    if ($program -ne 'Any') {
        $ruleParams['Program'] = $program
    }

    # ── Ports (TCP / UDP only) ────────────────────────────────────────────────
    if ($protocol -in @('TCP', 'UDP')) {
        $localPort  = Get-RandomPort
        $remotePort = Get-RandomPort
        if ($localPort  -ne 'Any') { $ruleParams['LocalPort']  = $localPort  }
        if ($remotePort -ne 'Any') { $ruleParams['RemotePort'] = $remotePort }
    }

    # ── Addresses ────────────────────────────────────────────────────────────
    if ($remoteAddr -ne 'Any') { $ruleParams['RemoteAddress'] = $remoteAddr }
    if ($localAddr  -ne 'Any') { $ruleParams['LocalAddress']  = $localAddr  }

    # ── Service (only meaningful with svchost or unconstrained program) ───────
    if ($service -ne 'Any' -and ($program -like '*svchost*' -or $program -eq 'Any')) {
        $ruleParams['Service'] = $service
    }

    # ── Create ────────────────────────────────────────────────────────────────
    try {
        New-NetFirewallRule @ruleParams | Out-Null
        $successCount++
    }
    catch {
        $failCount++
        Write-Warning "Rule $i ('$ruleName') failed: $($_.Exception.Message)"
    }

    if ($i % 50 -eq 0) {
        Write-Host ("  [{0,3}/{1}]  OK: {2}  Failed: {3}" -f $i, $RuleCount, $successCount, $failCount) -ForegroundColor Yellow
    }
}

# ─── Save GPO ────────────────────────────────────────────────────────────────

Write-Host "[*] Saving GPO..." -ForegroundColor Cyan
Save-NetGPO -GPOSession $GPOSession
Write-Host "[+] GPO saved." -ForegroundColor Green

# ─── Optional: link to OU ────────────────────────────────────────────────────

if ($LinkOU) {
    Write-Host "[*] Linking GPO to OU: $LinkOU..." -ForegroundColor Cyan
    try {
        New-GPLink -Name $GPOName -Domain $Domain -Target $LinkOU | Out-Null
        Write-Host "[+] GPO linked to $LinkOU." -ForegroundColor Green
    }
    catch {
        Write-Warning "GPO link failed: $($_.Exception.Message)"
    }
}

# ─── Summary ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host ("=" * 54) -ForegroundColor Cyan
Write-Host " GPO Creation Summary" -ForegroundColor Cyan
Write-Host ("=" * 54) -ForegroundColor Cyan
Write-Host (" GPO Name     : {0}" -f $GPOName)
Write-Host (" Domain       : {0}" -f $Domain)
Write-Host (" GPO ID       : {0}" -f $GPO.Id)
Write-Host (" Rules OK     : {0}" -f $successCount)
Write-Host (" Rules Failed : {0}" -f $failCount)
if ($LinkOU) { Write-Host (" Linked OU    : {0}" -f $LinkOU) }
Write-Host ("=" * 54) -ForegroundColor Cyan
