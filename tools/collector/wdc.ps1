#requires -version 2.0
<#
Windows .NET Discovery Collector 1.1.2
Read-only discovery: the script reads system state and writes only beneath OutputRoot.
No network upload, installation, configuration change, service/task control, or secret export.
#>

param(
    [string]$OutputRoot = "",
    [ValidateRange(1, 1440)][int]$Samples = 6,
    [ValidateRange(1, 3600)][int]$IntervalSeconds = 10,
    [ValidateRange(100, 100000)][int]$MaxFilesPerApp = 5000,
    [ValidateRange(10, 5000)][int]$MaxEventRecords = 200,
    [switch]$SkipConfigMetadata,
    [switch]$NoNetworkSampling,
    [switch]$NoPerformance,
    [switch]$NoEventLogs,
    [switch]$NoIis,
    [switch]$NoZip,
    [switch]$Help
)

$script:ToolVersion = "1.1.2"
$script:SchemaVersion = "1.1"
$script:Coverage = New-Object System.Collections.ArrayList
$script:Findings = New-Object System.Collections.ArrayList
$script:Data = @{}
$script:OutputDirectory = $null
$script:EvidenceDirectory = $null
$script:CsvDirectory = $null
$script:StartTime = Get-Date
$script:IsAdmin = $false

function Show-Banner {
    Write-Host "============================================================"
    Write-Host " Windows .NET Discovery Collector"
    Write-Host " Version: $script:ToolVersion"
    Write-Host " Created by: gosft (Thailand) co., ltd."
    Write-Host "============================================================"
}

function Show-Usage {
    Show-Banner
    Write-Host ""
    Write-Host "Usage: wdc.cmd [options]"
    Write-Host "  -OutputRoot <path>          Parent directory for results (default: current directory)"
    Write-Host "  -Samples <1-1440>          Network/performance sample count (default: 6)"
    Write-Host "  -IntervalSeconds <1-3600>  Delay between samples (default: 10)"
    Write-Host "  -MaxFilesPerApp <n>        Bounded binary/config inventory per app (default: 5000)"
    Write-Host "  -MaxEventRecords <n>       Maximum recent records per event log (default: 200)"
    Write-Host "  -SkipConfigMetadata        Do not inspect config section/key metadata"
    Write-Host "  -NoNetworkSampling         Skip netstat sampling"
    Write-Host "  -NoPerformance             Skip WMI performance sampling"
    Write-Host "  -NoEventLogs               Skip recent Application/System warnings and errors"
    Write-Host "  -NoIis                     Skip IIS discovery"
    Write-Host "  -NoZip                     Do not create a result ZIP"
    Write-Host "  -Help                      Show this help"
    Write-Host ""
    Write-Host "Example: wdc.cmd -OutputRoot D:\Discovery -Samples 60 -IntervalSeconds 60"
}

if ($Help) { Show-Usage; exit 0 }

function New-Record {
    param([hashtable]$Properties)
    return (New-Object PSObject -Property $Properties)
}

function Protect-Text {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    $text = [string]$Value
    $patterns = @(
        '(?i)(password|passwd|pwd|secret|client_secret|token|access_token|api[_-]?key)\s*([=:])\s*([^;\s&]+)',
        '(?i)(User\s*ID|UID)\s*=\s*([^;]+)',
        '(?i)(Authorization\s*:\s*)(Basic|Bearer)\s+\S+',
        '(?i)(--?(password|passwd|pwd|secret|token|api[_-]?key)\s+)(\S+)'
    )
    $text = [regex]::Replace($text, $patterns[0], '$1$2[REDACTED]')
    $text = [regex]::Replace($text, $patterns[1], '$1=[REDACTED]')
    $text = [regex]::Replace($text, $patterns[2], '$1$2 [REDACTED]')
    $text = [regex]::Replace($text, $patterns[3], '$1[REDACTED]')
    return $text
}

function ConvertTo-SafeFileName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return "unknown" }
    foreach ($c in [IO.Path]::GetInvalidFileNameChars()) { $Name = $Name.Replace([string]$c, "_") }
    return $Name
}

function Write-Utf8Text {
    param([string]$Path, [object]$Content)
    $text = if ($Content -is [array]) { [string]::Join([Environment]::NewLine, [string[]]$Content) } else { [string]$Content }
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true
    [IO.File]::WriteAllText($Path, $text, $encoding)
}

function Export-Records {
    param([string]$Name, [object[]]$Records)
    $safe = ConvertTo-SafeFileName $Name
    $path = Join-Path $script:CsvDirectory ($safe + ".csv")
    $items = @($Records)
    if ($items.Count -gt 0) {
        $items | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    } else {
        Write-Utf8Text $path "Status,Message`r`nEMPTY,`"No records returned`""
    }
    $script:Data[$Name] = $items
}

function Add-Coverage {
    param([string]$Collector, [string]$Status, [string]$Message, [datetime]$Started)
    $duration = [math]::Round(((Get-Date) - $Started).TotalSeconds, 3)
    [void]$script:Coverage.Add((New-Record @{
        Collector = $Collector; Status = $Status; Message = (Protect-Text $Message); DurationSeconds = $duration
    }))
}

function Add-Finding {
    param([string]$Severity, [string]$Code, [string]$Title, [string]$Evidence, [string]$Recommendation)
    [void]$script:Findings.Add((New-Record @{
        Severity = $Severity; Code = $Code; Title = $Title; Evidence = (Protect-Text $Evidence); Recommendation = $Recommendation
    }))
}

function Invoke-Collector {
    param([string]$Name, [scriptblock]$Action, [switch]$Skip, [string]$SkipReason = "Skipped by option")
    $started = Get-Date
    if ($Skip) {
        Write-Host "[WDC] Skipped collector: $Name ($SkipReason)"
        Add-Coverage $Name "SKIPPED" $SkipReason $started
        return
    }
    Write-Host "[WDC] Running collector: $Name..."
    try {
        & $Action
        Add-Coverage $Name "AVAILABLE" "Collection completed" $started
        $elapsed = ((Get-Date) - $started).TotalSeconds.ToString("0.00", [Globalization.CultureInfo]::InvariantCulture)
        Write-Host "[WDC] Completed collector: $Name ($elapsed seconds)"
    } catch {
        Add-Coverage $Name "ERROR" $_.Exception.Message $started
        $elapsed = ((Get-Date) - $started).TotalSeconds.ToString("0.00", [Globalization.CultureInfo]::InvariantCulture)
        Write-Warning ("Collector failed: " + $Name + " (" + $elapsed + " seconds) - " + (Protect-Text $_.Exception.Message))
    }
}

function Invoke-ReadOnlyCommand {
    param([string]$FilePath, [string[]]$Arguments, [string]$EvidenceName)
    if (-not (Test-Path $FilePath) -and -not (Get-Command $FilePath -ErrorAction SilentlyContinue)) {
        throw "Command not found: $FilePath"
    }
    $lines = & $FilePath @Arguments 2>&1 | ForEach-Object { Protect-Text $_ }
    $exitCode = $LASTEXITCODE
    $path = Join-Path $script:EvidenceDirectory $EvidenceName
    Write-Utf8Text $path $lines
    if ($exitCode -ne 0) { throw "Read-only command failed with exit code ${exitCode}: $FilePath" }
    return @($lines)
}

function Get-WmiSafe {
    param([string]$Class, [string]$Namespace = "root\cimv2", [string]$Filter = "")
    if ([string]::IsNullOrEmpty($Filter)) {
        return @(Get-WmiObject -Namespace $Namespace -Class $Class -ErrorAction Stop)
    }
    return @(Get-WmiObject -Namespace $Namespace -Class $Class -Filter $Filter -ErrorAction Stop)
}

function Convert-WmiDate {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) { return "" }
    try { return [Management.ManagementDateTimeConverter]::ToDateTime([string]$Value).ToString("s") } catch { return [string]$Value }
}

function Get-FileSha256 {
    param([string]$Path)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        $stream = [IO.File]::OpenRead($Path)
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "").ToLowerInvariant() }
        finally { $stream.Dispose(); $sha.Dispose() }
    } catch { return "HASH_ERROR" }
}

function Get-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-SystemInventory {
    $os = @(Get-WmiSafe "Win32_OperatingSystem")[0]
    $cs = @(Get-WmiSafe "Win32_ComputerSystem")[0]
    $bios = @(Get-WmiSafe "Win32_BIOS")[0]
    $cpu = @(Get-WmiSafe "Win32_Processor")
    $result = @(New-Record @{
        ComputerName = $env:COMPUTERNAME
        OSCaption = $os.Caption
        OSVersion = $os.Version
        BuildNumber = $os.BuildNumber
        ServicePack = $os.CSDVersion
        OSArchitecture = $os.OSArchitecture
        InstallDate = Convert-WmiDate $os.InstallDate
        LastBoot = Convert-WmiDate $os.LastBootUpTime
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        Domain = $cs.Domain
        DomainRole = $cs.DomainRole
        TotalMemoryGB = [math]::Round(([double]$cs.TotalPhysicalMemory / 1GB), 2)
        LogicalProcessors = $cs.NumberOfLogicalProcessors
        ProcessorNames = (($cpu | ForEach-Object { $_.Name }) -join "; ")
        BiosVersion = (($bios.SMBIOSBIOSVersion, $bios.Version | Where-Object { $_ }) -join "; ")
        TimeZone = ([TimeZone]::CurrentTimeZone.StandardName)
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        DotNetClrVersion = [Environment]::Version.ToString()
        CollectorElevated = $script:IsAdmin
    })
    Export-Records "system" $result
    if ([version]$os.Version -lt [version]"10.0") {
        Add-Finding "HIGH" "OS-LIFECYCLE-REVIEW" "Operating system requires lifecycle and cloud-image review" ($os.Caption + " " + $os.Version) "Validate vendor support, cloud import eligibility, and target-OS compatibility; do not assume an equivalent marketplace image exists."
    }
}

function Get-StorageInventory {
    $records = @()
    foreach ($d in @(Get-WmiSafe "Win32_LogicalDisk")) {
        $size = 0; $free = 0; $freePct = 0
        if ($d.Size) { $size = [math]::Round(([double]$d.Size / 1GB), 2) }
        if ($d.FreeSpace) { $free = [math]::Round(([double]$d.FreeSpace / 1GB), 2) }
        if ($d.Size -and [double]$d.Size -gt 0) { $freePct = [math]::Round((100 * [double]$d.FreeSpace / [double]$d.Size), 2) }
        $records += New-Record @{
            DeviceID=$d.DeviceID; VolumeName=$d.VolumeName; DriveType=$d.DriveType; FileSystem=$d.FileSystem
            SizeGB=$size; FreeGB=$free; FreePercent=$freePct; ProviderName=$d.ProviderName; VolumeSerialNumber=$d.VolumeSerialNumber
        }
        if ($d.DriveType -eq 3 -and $freePct -lt 15) {
            Add-Finding "MEDIUM" "DISK-LOW-FREE" "Local disk has less than 15% free space" ($d.DeviceID + " free=" + $freePct + "%") "Include growth and migration staging space in target sizing."
        }
    }
    Export-Records "storage" $records
}

function Get-NetworkInventory {
    $records = @()
    foreach ($n in @(Get-WmiSafe "Win32_NetworkAdapterConfiguration" "root\cimv2" "IPEnabled=True")) {
        $records += New-Record @{
            Description=$n.Description; MACAddress=$n.MACAddress; DHCPEnabled=$n.DHCPEnabled; DHCPServer=$n.DHCPServer
            IPAddresses=(@($n.IPAddress) -join "; "); Subnets=(@($n.IPSubnet) -join "; ")
            DefaultGateways=(@($n.DefaultIPGateway) -join "; "); DNSServers=(@($n.DNSServerSearchOrder) -join "; ")
            DNSDomain=$n.DNSDomain; WINSPrimary=$n.WINSPrimaryServer; WINSSecondary=$n.WINSSecondaryServer
        }
    }
    Export-Records "network_adapters" $records
    Invoke-ReadOnlyCommand "route.exe" @("print") "route-print.txt" | Out-Null
    Invoke-ReadOnlyCommand "netsh.exe" @("winhttp", "show", "proxy") "winhttp-proxy.txt" | Out-Null
    Invoke-ReadOnlyCommand "ipconfig.exe" @("/all") "ipconfig-all.txt" | Out-Null
}

function Get-InstalledSoftwareInventory {
    $records = @()
    $roots = @(
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; View="64/native" },
        @{ Path="HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; View="32" }
    )
    foreach ($root in $roots) {
        foreach ($item in @(Get-ItemProperty -Path $root.Path -ErrorAction SilentlyContinue)) {
            if (-not [string]::IsNullOrEmpty([string]$item.DisplayName)) {
                $records += New-Record @{
                    DisplayName=$item.DisplayName; DisplayVersion=$item.DisplayVersion; Publisher=$item.Publisher
                    InstallDate=$item.InstallDate; InstallLocation=$item.InstallLocation; ArchitectureView=$root.View
                    RegistryKey=$item.PSChildName
                }
            }
        }
    }
    Export-Records "installed_software" ($records | Sort-Object DisplayName, DisplayVersion -Unique)
}

function Get-HotfixInventory {
    $records = @()
    foreach ($h in @(Get-WmiSafe "Win32_QuickFixEngineering")) {
        $records += New-Record @{ HotFixID=$h.HotFixID; Description=$h.Description; InstalledBy=$h.InstalledBy; InstalledOn=$h.InstalledOn; Caption=$h.Caption }
    }
    Export-Records "hotfixes" $records
}

function Get-WindowsFeatureEvidence {
    $dism = Join-Path $env:WINDIR "System32\dism.exe"
    if (Test-Path $dism) { Invoke-ReadOnlyCommand $dism @("/Online", "/Get-Features", "/Format:Table") "windows-features-dism.txt" | Out-Null }
    else { throw "DISM not available" }
}

function Get-ServiceInventory {
    $records = @()
    foreach ($s in @(Get-WmiSafe "Win32_Service")) {
        $requiredServices = @(); $dependentServices = @()
        try {
            $serviceObject = Get-Service -Name $s.Name -ErrorAction Stop
            $requiredServices = @($serviceObject.ServicesDependedOn | ForEach-Object { $_.Name })
            $dependentServices = @($serviceObject.DependentServices | ForEach-Object { $_.Name })
        } catch { }
        $records += New-Record @{
            Name=$s.Name; DisplayName=$s.DisplayName; State=$s.State; StartMode=$s.StartMode; StartName=$s.StartName
            ProcessId=$s.ProcessId; PathName=(Protect-Text $s.PathName); ServiceType=$s.ServiceType; Description=$s.Description
            RequiredServices=($requiredServices -join "; "); DependentServices=($dependentServices -join "; ")
        }
    }
    Export-Records "services" $records
}

function Get-ProcessOwner {
    param([object]$Process)
    try {
        $owner = $Process.GetOwner()
        if ($owner.ReturnValue -eq 0) { return (($owner.Domain + "\" + $owner.User).Trim("\")) }
    } catch { }
    return ""
}

function Get-ProcessInventory {
    $records = @()
    foreach ($p in @(Get-WmiSafe "Win32_Process")) {
        $records += New-Record @{
            ProcessId=$p.ProcessId; ParentProcessId=$p.ParentProcessId; Name=$p.Name; ExecutablePath=$p.ExecutablePath
            CommandLine=(Protect-Text $p.CommandLine); Owner=(Get-ProcessOwner $p); CreationDate=(Convert-WmiDate $p.CreationDate)
            WorkingSetMB=[math]::Round(([double]$p.WorkingSetSize / 1MB), 2)
        }
    }
    Export-Records "processes" $records
}

function Get-ScheduledTaskFolder {
    param([object]$Folder, [System.Collections.ArrayList]$Records)
    foreach ($task in @($Folder.GetTasks(1))) {
        $definition = $task.Definition
        $actions = New-Object System.Collections.ArrayList
        foreach ($a in @($definition.Actions)) {
            $detail = "Type=" + $a.Type
            try { if ($a.Path) { $detail += ";Path=" + $a.Path } } catch { }
            try { if ($a.Arguments) { $detail += ";Arguments=" + $a.Arguments } } catch { }
            try { if ($a.WorkingDirectory) { $detail += ";WorkingDirectory=" + $a.WorkingDirectory } } catch { }
            [void]$actions.Add((Protect-Text $detail))
        }
        $triggerTypes = @()
        foreach ($t in @($definition.Triggers)) { $triggerTypes += [string]$t.Type }
        [void]$Records.Add((New-Record @{
            Name=$task.Name; Path=$task.Path; Enabled=$task.Enabled; State=$task.State
            LastRunTime=$task.LastRunTime; NextRunTime=$task.NextRunTime; LastTaskResult=$task.LastTaskResult
            Author=$definition.RegistrationInfo.Author; UserId=$definition.Principal.UserId
            LogonType=$definition.Principal.LogonType; RunLevel=$definition.Principal.RunLevel
            Actions=($actions -join " | "); TriggerTypes=($triggerTypes -join "; ")
        }))
        $isWindowsBuiltIn = ([string]$task.Path).StartsWith("\Microsoft\Windows\", [StringComparison]::OrdinalIgnoreCase)
        if (-not $isWindowsBuiltIn -and $task.LastTaskResult -ne 0 -and $task.LastTaskResult -ne 267011 -and $task.LastTaskResult -ne 267009) {
            Add-Finding "MEDIUM" "TASK-LAST-RESULT" "Scheduled task has a non-success last result" ($task.Path + " result=" + $task.LastTaskResult) "Confirm whether this task is a migration dependency and reproduce its identity, trigger, action, and operating context."
        }
    }
    foreach ($child in @($Folder.GetFolders(0))) { Get-ScheduledTaskFolder $child $Records }
}

function Get-ScheduledTaskInventory {
    $service = New-Object -ComObject "Schedule.Service"
    $service.Connect()
    $records = New-Object System.Collections.ArrayList
    Get-ScheduledTaskFolder ($service.GetFolder("\")) $records
    Export-Records "scheduled_tasks" @($records)
}

function Resolve-DotNetFrameworkVersion {
    param([int]$Release)
    if ($Release -ge 533320) { return "4.8.1 or later" }
    if ($Release -ge 528040) { return "4.8" }
    if ($Release -ge 461808) { return "4.7.2" }
    if ($Release -ge 461308) { return "4.7.1" }
    if ($Release -ge 460798) { return "4.7" }
    if ($Release -ge 394802) { return "4.6.2" }
    if ($Release -ge 394254) { return "4.6.1" }
    if ($Release -ge 393295) { return "4.6" }
    if ($Release -ge 379893) { return "4.5.2" }
    if ($Release -ge 378675) { return "4.5.1" }
    if ($Release -ge 378389) { return "4.5" }
    return "Unknown release"
}

function Get-DotNetInventory {
    $records = @()
    $roots = @(
        @{Path="HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP"; View="64/native"},
        @{Path="HKLM:\SOFTWARE\Wow6432Node\Microsoft\NET Framework Setup\NDP"; View="32"}
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root.Path)) { continue }
        foreach ($key in @(Get-ChildItem $root.Path -Recurse -ErrorAction SilentlyContinue)) {
            $v = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
            if ($v -and ($v.Version -or $v.Release -or $v.Install -eq 1)) {
                $resolved = ""
                if ($v.Release) { $resolved = Resolve-DotNetFrameworkVersion ([int]$v.Release) }
                $records += New-Record @{
                    Family=".NET Framework"; Name=$key.PSChildName; Version=$v.Version; Release=$v.Release
                    ResolvedVersion=$resolved; Install=$v.Install; ServicePack=$v.SP; ArchitectureView=$root.View
                    RegistryPath=$key.Name
                }
            }
        }
    }
    Export-Records "dotnet_framework" ($records | Sort-Object RegistryPath, ArchitectureView -Unique)
    $releases = @($records | Where-Object { $_.Release } | ForEach-Object { [int]$_.Release } | Sort-Object -Descending)
    if ($releases.Count -gt 0 -and $releases[0] -lt 528040) {
        Add-Finding "MEDIUM" "DOTNET-FRAMEWORK-COMPAT" ".NET Framework installation is older than 4.8" ("highestRelease=" + $releases[0] + ", resolved=" + (Resolve-DotNetFrameworkVersion $releases[0])) "Assess target-OS support and application compatibility; prefer testing on a supported OS with .NET Framework 4.8 where the application permits."
    }

    $runtimeRecords = @()
    $dotnet = Get-Command "dotnet.exe" -ErrorAction SilentlyContinue
    if ($dotnet) {
        $lines = Invoke-ReadOnlyCommand $dotnet.Path @("--list-runtimes") "dotnet-list-runtimes.txt"
        foreach ($line in $lines) {
            if ([string]$line -match '^([^\s]+)\s+([^\s]+)\s+\[(.+)\]$') {
                $runtimeRecords += New-Record @{ Runtime=$matches[1]; Version=$matches[2]; Path=$matches[3] }
            }
        }
        Invoke-ReadOnlyCommand $dotnet.Path @("--list-sdks") "dotnet-list-sdks.txt" | Out-Null
    }
    Export-Records "dotnet_runtimes" $runtimeRecords
}

function Get-CertificateInventory {
    $records = @()
    foreach ($location in @("LocalMachine", "CurrentUser")) {
        foreach ($storeName in @("My", "Root", "CA", "WebHosting")) {
            try {
                if ($location -eq "LocalMachine") { $storeLocation = [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine }
                else { $storeLocation = [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser }
                $store = New-Object -TypeName Security.Cryptography.X509Certificates.X509Store -ArgumentList @($storeName, $storeLocation)
                $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                foreach ($c in @($store.Certificates)) {
                    $records += New-Record @{
                        Location=$location; Store=$storeName; Subject=$c.Subject; Issuer=$c.Issuer; Thumbprint=$c.Thumbprint
                        SerialNumber=$c.SerialNumber; NotBefore=$c.NotBefore.ToString("s"); NotAfter=$c.NotAfter.ToString("s")
                        HasPrivateKey=$c.HasPrivateKey; SignatureAlgorithm=$c.SignatureAlgorithm.FriendlyName
                    }
                    if (($storeName -eq "My" -or $storeName -eq "WebHosting") -and $c.NotAfter -lt (Get-Date)) {
                        Add-Finding "HIGH" "CERT-EXPIRED" "Certificate is expired" ($location + "/" + $storeName + " " + $c.Subject + " " + $c.NotAfter) "Determine whether the certificate is in active use and replace it before migration."
                    } elseif (($storeName -eq "My" -or $storeName -eq "WebHosting") -and $c.NotAfter -lt (Get-Date).AddDays(90)) {
                        Add-Finding "MEDIUM" "CERT-EXPIRY" "Certificate expires within 90 days" ($location + "/" + $storeName + " " + $c.Subject + " " + $c.NotAfter) "Plan certificate renewal and target-platform import/binding."
                    }
                }
                $store.Close()
            } catch { }
        }
    }
    Export-Records "certificates" ($records | Sort-Object Location, Store, Thumbprint -Unique)
}

function Get-LocalIdentityInventory {
    $users = @()
    foreach ($u in @(Get-WmiSafe "Win32_UserAccount" "root\cimv2" "LocalAccount=True")) {
        $users += New-Record @{ Name=$u.Name; SID=$u.SID; Disabled=$u.Disabled; Lockout=$u.Lockout; PasswordRequired=$u.PasswordRequired; Status=$u.Status }
    }
    Export-Records "local_users" $users
    $groups = @()
    foreach ($g in @(Get-WmiSafe "Win32_Group" "root\cimv2" "LocalAccount=True")) {
        $groups += New-Record @{ Name=$g.Name; SID=$g.SID; Description=$g.Description; Status=$g.Status }
    }
    Export-Records "local_groups" $groups
    $envNames = @()
    foreach ($scope in @("Machine", "User")) {
        if ($scope -eq "Machine") { $target = [EnvironmentVariableTarget]::Machine } else { $target = [EnvironmentVariableTarget]::User }
        $vars = [Environment]::GetEnvironmentVariables($target)
        foreach ($name in $vars.Keys) { $envNames += New-Record @{ Scope=$scope; Name=$name; Value="NOT_COLLECTED" } }
    }
    Export-Records "environment_variable_names" $envNames
}

function Get-ShareInventory {
    $records = @()
    foreach ($s in @(Get-WmiSafe "Win32_Share")) {
        $records += New-Record @{ Name=$s.Name; Path=$s.Path; Type=$s.Type; Description=$s.Description; MaximumAllowed=$s.MaximumAllowed }
    }
    Export-Records "shares" $records
}

function Get-FirewallEvidence {
    Invoke-ReadOnlyCommand "netsh.exe" @("advfirewall", "show", "allprofiles") "firewall-profiles.txt" | Out-Null
    Invoke-ReadOnlyCommand "netsh.exe" @("advfirewall", "firewall", "show", "rule", "name=all", "verbose") "firewall-rules.txt" | Out-Null
}

function Split-Endpoint {
    param([string]$Address)
    $hostPart = ""; $portPart = ""
    if ($Address -match '^\[([^\]]+)\]:(\*|\d+)$') { $hostPart=$matches[1]; $portPart=$matches[2] }
    elseif ($Address -match '^(.*):(\*|\d+)$') { $hostPart=$matches[1]; $portPart=$matches[2] }
    else { $hostPart=$Address }
    return @((Protect-Text $hostPart), $portPart)
}

function Get-NetstatSample {
    param([int]$SampleNumber, [datetime]$Timestamp, [hashtable]$ProcessMap)
    $records = @()
    $lines = & netstat.exe -ano 2>&1
    foreach ($line in $lines) {
        $parts = @(([string]$line).Trim() -split '\s+')
        if ($parts.Count -lt 4) { continue }
        $proto = $parts[0].ToUpperInvariant()
        if ($proto -ne "TCP" -and $proto -ne "UDP") { continue }
        if ($proto -eq "TCP" -and $parts.Count -ge 5) { $local=$parts[1]; $remote=$parts[2]; $state=$parts[3]; $processId=$parts[4] }
        elseif ($proto -eq "UDP" -and $parts.Count -ge 4) { $local=$parts[1]; $remote=$parts[2]; $state=""; $processId=$parts[3] }
        else { continue }
        $localParts = Split-Endpoint $local; $remoteParts = Split-Endpoint $remote
        $proc = $null; if ($ProcessMap.ContainsKey([string]$processId)) { $proc = $ProcessMap[[string]$processId] }
        $processName = ""; $executablePath = ""
        if ($proc) { $processName = $proc.Name; $executablePath = $proc.ExecutablePath }
        $records += New-Record @{
            Sample=$SampleNumber; Timestamp=$Timestamp.ToString("s"); Protocol=$proto
            LocalAddress=$localParts[0]; LocalPort=$localParts[1]; RemoteAddress=$remoteParts[0]; RemotePort=$remoteParts[1]
            State=$state; ProcessId=$processId; ProcessName=$processName; ExecutablePath=$executablePath
        }
    }
    return $records
}

function Get-PerformanceSample {
    param([int]$SampleNumber, [datetime]$Timestamp)
    $records = @()
    $stamp = $Timestamp.ToString("s")
    try {
        $p = @(Get-WmiSafe "Win32_PerfFormattedData_PerfOS_Processor" "root\cimv2" "Name='_Total'")[0]
        $records += New-Record @{Sample=$SampleNumber;Timestamp=$stamp;Category="Processor";Instance="_Total";Metric="PercentProcessorTime";Value=$p.PercentProcessorTime}
    } catch { }
    try {
        $m = @(Get-WmiSafe "Win32_PerfFormattedData_PerfOS_Memory")[0]
        $records += New-Record @{Sample=$SampleNumber;Timestamp=$stamp;Category="Memory";Instance="_Total";Metric="AvailableMBytes";Value=$m.AvailableMBytes}
        $records += New-Record @{Sample=$SampleNumber;Timestamp=$stamp;Category="Memory";Instance="_Total";Metric="PagesPerSec";Value=$m.PagesPerSec}
    } catch { }
    try {
        foreach ($d in @(Get-WmiSafe "Win32_PerfFormattedData_PerfDisk_LogicalDisk")) {
            if ($d.Name -eq "_Total" -or $d.Name -match '^[A-Z]:$') {
                $records += New-Record @{Sample=$SampleNumber;Timestamp=$stamp;Category="LogicalDisk";Instance=$d.Name;Metric="PercentDiskTime";Value=$d.PercentDiskTime}
                $records += New-Record @{Sample=$SampleNumber;Timestamp=$stamp;Category="LogicalDisk";Instance=$d.Name;Metric="DiskBytesPerSec";Value=$d.DiskBytesPerSec}
            }
        }
    } catch { }
    try {
        foreach ($n in @(Get-WmiSafe "Win32_PerfFormattedData_Tcpip_NetworkInterface")) {
            $records += New-Record @{Sample=$SampleNumber;Timestamp=$stamp;Category="Network";Instance=$n.Name;Metric="BytesTotalPerSec";Value=$n.BytesTotalPerSec}
        }
    } catch { }
    return $records
}

function Get-SampledTelemetry {
    $connections = @(); $performance = @()
    $processMap = @{}
    foreach ($p in @(Get-WmiSafe "Win32_Process")) { $processMap[[string]$p.ProcessId] = $p }
    for ($i=1; $i -le $Samples; $i++) {
        Write-Host ("[WDC] Collecting telemetry sample {0} of {1}..." -f $i, $Samples)
        $now = Get-Date
        if (-not $NoNetworkSampling) { $connections += Get-NetstatSample $i $now $processMap }
        if (-not $NoPerformance) { $performance += Get-PerformanceSample $i $now }
        if ($i -lt $Samples) { Start-Sleep -Seconds $IntervalSeconds }
    }
    if (-not $NoNetworkSampling) {
        Export-Records "network_connections_samples" $connections
        $aggregate = @()
        foreach ($g in @($connections | Group-Object Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessId,ProcessName)) {
            $first = @($g.Group | Sort-Object Timestamp)[0]
            $last = @($g.Group | Sort-Object Timestamp -Descending)[0]
            $aggregate += New-Record @{
                Protocol=$first.Protocol; LocalAddress=$first.LocalAddress; LocalPort=$first.LocalPort
                RemoteAddress=$first.RemoteAddress; RemotePort=$first.RemotePort; State=$first.State
                ProcessId=$first.ProcessId; ProcessName=$first.ProcessName; ExecutablePath=$first.ExecutablePath
                FirstSeen=$first.Timestamp; LastSeen=$last.Timestamp; ObservationCount=$g.Count
            }
        }
        Export-Records "network_connections_aggregate" $aggregate
        $listenerKeys = @{}
        foreach ($row in @($connections | Where-Object { $_.State -eq "LISTENING" })) {
            $listenerKeys[($row.LocalPort + "|" + $row.ProcessId)] = $true
        }
        $edges = @()
        foreach ($row in @($aggregate | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne "*" -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" })) {
            $direction = "OUTBOUND_OR_UNKNOWN"
            if ($listenerKeys.ContainsKey(($row.LocalPort + "|" + $row.ProcessId))) { $direction = "INBOUND_TO_LOCAL_LISTENER" }
            if ($row.Protocol -eq "UDP") { $direction = "UNKNOWN_UDP" }
            $edges += New-Record @{
                SourceHost=$env:COMPUTERNAME; LocalProcess=$row.ProcessName; ProcessId=$row.ProcessId
                LocalAddress=$row.LocalAddress; LocalPort=$row.LocalPort; RemoteAddress=$row.RemoteAddress; RemotePort=$row.RemotePort
                Protocol=$row.Protocol; DirectionHeuristic=$direction; FirstSeen=$row.FirstSeen; LastSeen=$row.LastSeen; ObservationCount=$row.ObservationCount
            }
        }
        Export-Records "dependency_edges" $edges
    }
    if (-not $NoPerformance) { Export-Records "performance_samples" $performance }
}

function Get-RecentEventInventory {
    $records = @()
    foreach ($log in @("Application", "System")) {
        try {
            foreach ($e in @(Get-EventLog -LogName $log -EntryType Error,Warning -Newest $MaxEventRecords -ErrorAction Stop)) {
                $records += New-Record @{
                    LogName=$log; TimeGenerated=$e.TimeGenerated.ToString("s"); EntryType=$e.EntryType; Source=$e.Source
                    EventID=$e.EventID; Category=$e.Category; MachineName=$e.MachineName; Message=(Protect-Text $e.Message)
                }
            }
        } catch { Add-Coverage ("event_log_" + $log) "ERROR" $_.Exception.Message (Get-Date) }
    }
    Export-Records "recent_events" $records
}

function Get-MsmqInventory {
    $records = @()
    $service = Get-Service -Name "MSMQ" -ErrorAction SilentlyContinue
    if (-not $service) { Export-Records "msmq_queues" @(); return }
    try {
        foreach ($q in @(Get-WmiSafe "Win32_PerfFormattedData_msmq_MSMQQueue")) {
            $records += New-Record @{
                Name=$q.Name; MessagesInQueue=$q.MessagesInQueue; BytesInQueue=$q.BytesInQueue
                MessagesInJournalQueue=$q.MessagesInJournalQueue; BytesInJournalQueue=$q.BytesInJournalQueue
            }
        }
    } catch { }
    Export-Records "msmq_queues" $records
}

function Write-ManualContextTemplate {
    $rows = @(
        New-Record @{Field="SystemName";Value="";WhyNeeded="Correlates technical evidence across servers that form one system"}
        New-Record @{Field="Environment";Value="";WhyNeeded="Separates production, DR, UAT, test, and development behavior"}
        New-Record @{Field="BusinessCriticality";Value="";WhyNeeded="Sets migration risk controls, rehearsal depth, and approval level"}
        New-Record @{Field="BusinessHoursAndPeakWindows";Value="";WhyNeeded="Validates whether telemetry includes representative load"}
        New-Record @{Field="AllowedDowntime";Value="";WhyNeeded="Constrains cutover pattern and data synchronization method"}
        New-Record @{Field="RTO";Value="";WhyNeeded="Defines recovery design and operational test target"}
        New-Record @{Field="RPO";Value="";WhyNeeded="Defines backup, replication, and consistency requirements"}
        New-Record @{Field="DataClassificationAndResidency";Value="";WhyNeeded="Constrains cloud region, controls, and evidence handling"}
        New-Record @{Field="SourceCodeAvailable";Value="Unknown";WhyNeeded="Determines whether refactor/recompile is feasible"}
        New-Record @{Field="BuildPipelineAvailable";Value="Unknown";WhyNeeded="Determines whether deployable artifacts can be reproduced"}
        New-Record @{Field="VendorSupportAndLicense";Value="Unknown";WhyNeeded="Constrains OS/runtime/cloud changes and legal operation"}
        New-Record @{Field="BusinessOwner";Value="Unknown";WhyNeeded="Required for acceptance, outage, and retirement decisions"}
        New-Record @{Field="TestApprover";Value="Unknown";WhyNeeded="Required to define and sign off business-correctness tests"}
        New-Record @{Field="KnownUserJourneysOrTransactions";Value="";WhyNeeded="Turns infrastructure checks into application acceptance tests"}
        New-Record @{Field="CollectionWindowNotes";Value="";WhyNeeded="Explains peak, batch, idle, incident, or maintenance conditions"}
        New-Record @{Field="ChangeOrWorkTicket";Value="";WhyNeeded="Maintains authorization and chain of custody"}
    )
    Export-Records "manual_context_template" $rows
}

function Get-FilesBounded {
    param([string]$Root, [int]$Maximum)
    $result = New-Object System.Collections.ArrayList
    $queue = New-Object System.Collections.Queue
    if (Test-Path $Root -PathType Container) { $queue.Enqueue((Get-Item $Root -ErrorAction Stop)) }
    while ($queue.Count -gt 0 -and $result.Count -lt $Maximum) {
        $dir = $queue.Dequeue()
        foreach ($entry in @(Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue)) {
            if ($result.Count -ge $Maximum) { break }
            if ($entry.PSIsContainer) {
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $entry.Name -notmatch '^(node_modules|\.git|packages)$') { $queue.Enqueue($entry) }
            } else { [void]$result.Add($entry) }
        }
    }
    return @($result)
}

function Get-ConnectionStringMetadata {
    param([string]$ConnectionString)
    $allowed = @("server","data source","address","addr","network address","database","initial catalog","provider")
    $items = @()
    foreach ($pair in @($ConnectionString -split ';')) {
        $kv = @($pair -split '=', 2)
        if ($kv.Count -eq 2) {
            $key = $kv[0].Trim().ToLowerInvariant()
            if ($allowed -contains $key) { $items += ($kv[0].Trim() + "=" + (Protect-Text $kv[1].Trim())) }
        }
    }
    return ($items -join ";")
}

function ConvertTo-SafeUrlMetadata {
    param([string]$Value)
    try {
        $uri = New-Object -TypeName System.Uri -ArgumentList $Value
        if ($uri.IsAbsoluteUri -and ($uri.Scheme -eq "http" -or $uri.Scheme -eq "https" -or $uri.Scheme -eq "ftp")) {
            return ($uri.Scheme + "://" + $uri.Host + ":" + $uri.Port + $uri.AbsolutePath)
        }
    } catch { }
    return ""
}

function Read-SafeXmlFile {
    param([string]$Path)
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create($Path, $settings)
    try {
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
        return $document
    } finally { $reader.Close() }
}

function Get-ConfigMetadata {
    param([string]$Application, [object[]]$Files)
    $records = @()
    foreach ($file in @($Files | Where-Object { $_.Extension -eq ".config" -or $_.Name -ieq "web.config" })) {
        $sectionNames = @(); $appKeys = @(); $urlMetadata = @(); $connMetadata = @()
        try {
            $xml = Read-SafeXmlFile $file.FullName
            if ($xml.configuration) {
                foreach ($child in @($xml.configuration.ChildNodes)) { if ($child.NodeType -eq "Element") { $sectionNames += $child.Name } }
                foreach ($add in @($xml.configuration.appSettings.add)) {
                    if ($add.key) { $appKeys += [string]$add.key }
                    $url = ConvertTo-SafeUrlMetadata ([string]$add.value)
                    if ($url) { $urlMetadata += (([string]$add.key) + "=" + $url) }
                }
                foreach ($add in @($xml.configuration.connectionStrings.add)) {
                    $connMetadata += (([string]$add.name) + "|" + ([string]$add.providerName) + "|" + (Get-ConnectionStringMetadata ([string]$add.connectionString)))
                }
            }
            $parseStatus = "PARSED"
        } catch { $parseStatus = "PARSE_ERROR: " + (Protect-Text $_.Exception.Message) }
        $records += New-Record @{
            Application=$Application; ConfigPath=$file.FullName; LastWriteTime=$file.LastWriteTime.ToString("s"); SizeBytes=$file.Length
            ParseStatus=$parseStatus; Sections=($sectionNames -join "; "); AppSettingKeys=($appKeys -join "; ")
            SafeUrlMetadata=($urlMetadata -join " | "); ConnectionMetadata=($connMetadata -join " | ")
            RawValuesCollected=$false
        }
    }
    return $records
}

function Get-IisInventory {
    $appcmd = Join-Path $env:WINDIR "System32\inetsrv\appcmd.exe"
    if (-not (Test-Path $appcmd)) { throw "IIS appcmd.exe not found" }
    $siteLines = Invoke-ReadOnlyCommand $appcmd @("list", "site", "/xml") "iis-sites.xml"
    $appLines = Invoke-ReadOnlyCommand $appcmd @("list", "app", "/xml") "iis-applications.xml"
    $vdirLines = Invoke-ReadOnlyCommand $appcmd @("list", "vdir", "/xml") "iis-virtual-directories.xml"
    $poolLines = Invoke-ReadOnlyCommand $appcmd @("list", "apppool", "/xml") "iis-app-pools.xml"
    $sites=@(); $apps=@(); $vdirs=@(); $pools=@()
    try {
        [xml]$x = ($siteLines -join [Environment]::NewLine)
        foreach ($n in @($x.appcmd.SITE)) { $sites += New-Record @{Name=$n.'SITE.NAME';Id=$n.'SITE.ID';State=$n.'state';Bindings=$n.'bindings'} }
    } catch { }
    try {
        [xml]$x = ($appLines -join [Environment]::NewLine)
        foreach ($n in @($x.appcmd.APP)) { $apps += New-Record @{Name=$n.'APP.NAME';AppPool=$n.'APPPOOL.NAME';SiteName=$n.'SITE.NAME';Path=$n.path} }
    } catch { }
    try {
        [xml]$x = ($vdirLines -join [Environment]::NewLine)
        foreach ($n in @($x.appcmd.VDIR)) { $vdirs += New-Record @{Name=$n.'VDIR.NAME';Application=$n.'APP.NAME';PhysicalPath=$n.physicalPath} }
    } catch { }
    try {
        [xml]$x = ($poolLines -join [Environment]::NewLine)
        foreach ($n in @($x.appcmd.APPPOOL)) {
            $runtime = $n.managedRuntimeVersion; if (-not $runtime) { $runtime = $n.RuntimeVersion }
            $pipeline = $n.managedPipelineMode; if (-not $pipeline) { $pipeline = $n.PipelineMode }
            $pools += New-Record @{Name=$n.'APPPOOL.NAME';State=$n.state;ManagedRuntimeVersion=$runtime;ManagedPipelineMode=$pipeline}
        }
    } catch { }
    Export-Records "iis_sites" $sites
    Export-Records "iis_applications" $apps
    Export-Records "iis_virtual_directories" $vdirs
    Export-Records "iis_app_pools" $pools

    $binaryRecords=@(); $configRecords=@(); $seen=@{}
    foreach ($v in $vdirs) {
        $root = [Environment]::ExpandEnvironmentVariables([string]$v.PhysicalPath)
        if ([string]::IsNullOrEmpty($root) -or $seen.ContainsKey($root)) { continue }
        if ($root.StartsWith("\\")) {
            Add-Finding "MEDIUM" "IIS-REMOTE-PATH-NOT-SCANNED" "IIS application uses a UNC content path" ($v.Name + " root=" + $root) "Collector does not access remote paths. Inventory the file server separately and validate share identity, permissions, latency, and migration order."
            continue
        }
        $rootDrive = [IO.Path]::GetPathRoot($root).TrimEnd('\')
        $disk = $null
        try { $disk = @(Get-WmiSafe "Win32_LogicalDisk" "root\cimv2" ("DeviceID='" + $rootDrive.Replace("'", "''") + "'"))[0] } catch { }
        if ($disk -and $disk.DriveType -ne 3) {
            Add-Finding "MEDIUM" "IIS-NONLOCAL-PATH-NOT-SCANNED" "IIS application content is not on a fixed local disk" ($v.Name + " root=" + $root + " driveType=" + $disk.DriveType) "Inventory the backing storage separately and validate permissions and migration order."
            continue
        }
        if (-not (Test-Path $root -PathType Container)) { continue }
        $seen[$root]=$true
        Write-Host "[WDC] Scanning IIS application content: $root"
        $files = @(Get-FilesBounded $root $MaxFilesPerApp)
        if ($files.Count -ge $MaxFilesPerApp) {
            Add-Finding "MEDIUM" "FILE-INVENTORY-CAPPED" "Application file inventory reached its configured cap" ($v.Name + " root=" + $root + " cap=" + $MaxFilesPerApp) "Increase MaxFilesPerApp or inspect the application tree separately before final migration planning."
        }
        foreach ($f in @($files | Where-Object { $_.Extension -match '^\.(dll|exe)$' })) {
            $vi=$null; try {$vi=$f.VersionInfo} catch {}
            $hash = if ($f.Length -le 100MB) { Get-FileSha256 $f.FullName } else { "SKIPPED_GT_100MB" }
            $fileVersion = ""; $productVersion = ""
            if ($vi) { $fileVersion = $vi.FileVersion; $productVersion = $vi.ProductVersion }
            $binaryRecords += New-Record @{
                Application=$v.Name; Root=$root; Path=$f.FullName; Extension=$f.Extension; SizeBytes=$f.Length
                LastWriteTime=$f.LastWriteTime.ToString("s"); FileVersion=$fileVersion; ProductVersion=$productVersion; SHA256=$hash
            }
        }
        if (-not $SkipConfigMetadata) { $configRecords += Get-ConfigMetadata $v.Name $files }
    }
    Export-Records "application_binaries" $binaryRecords
    if (-not $SkipConfigMetadata) { Export-Records "config_metadata" $configRecords }

    $usedPools = @{}
    foreach ($a in $apps) { if ($a.AppPool) { $usedPools[[string]$a.AppPool] = $true } }
    foreach ($p in $pools) {
        $isUsed = $usedPools.ContainsKey([string]$p.Name)
        if ($isUsed -and $p.ManagedRuntimeVersion -and $p.ManagedRuntimeVersion -ne "v4.0") {
            Add-Finding "MEDIUM" "IIS-RUNTIME-COMPAT" "IIS application pool does not use CLR v4.0" ($p.Name + " runtime=" + $p.ManagedRuntimeVersion) "Validate application compatibility with a supported .NET/runtime and target OS before replatforming."
        }
        if ($isUsed -and $p.ManagedPipelineMode -eq "Classic") {
            Add-Finding "MEDIUM" "IIS-CLASSIC-PIPELINE" "IIS application pool uses Classic pipeline" $p.Name "Test on the target IIS version; Classic-pipeline behavior may constrain modernization options."
        }
    }
}

function ConvertTo-HtmlEncoded {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return [Security.SecurityElement]::Escape([string]$Value)
}

function New-HtmlTable {
    param([string]$Title, [object[]]$Rows, [int]$Limit = 200)
    $items = @($Rows | Select-Object -First $Limit)
    $html = New-Object Text.StringBuilder
    [void]$html.Append("<section><h2>" + (ConvertTo-HtmlEncoded $Title) + "</h2>")
    if ($items.Count -eq 0) { [void]$html.Append("<p class='muted'>No records.</p></section>"); return $html.ToString() }
    $properties = @($items[0].PSObject.Properties | ForEach-Object { $_.Name })
    [void]$html.Append("<div class='table-wrap'><table><thead><tr>")
    foreach ($p in $properties) { [void]$html.Append("<th>" + (ConvertTo-HtmlEncoded $p) + "</th>") }
    [void]$html.Append("</tr></thead><tbody>")
    foreach ($row in $items) {
        [void]$html.Append("<tr>")
        foreach ($p in $properties) { [void]$html.Append("<td>" + (ConvertTo-HtmlEncoded $row.$p) + "</td>") }
        [void]$html.Append("</tr>")
    }
    [void]$html.Append("</tbody></table></div>")
    if (@($Rows).Count -gt $Limit) { [void]$html.Append(("<p class='muted'>Showing first {0} of {1}. Full data is in CSV.</p>" -f $Limit, @($Rows).Count)) }
    [void]$html.Append("</section>")
    return $html.ToString()
}

function Normalize-ApplicationName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return "" }
    return $Name.TrimEnd('/')
}

function Get-OsLifecycleAssessment {
    param([string]$Caption)
    $asOf = "2026-08-21"
    if ($Caption -match 'Windows Server 2025') { return "Mainstream support ends 2029-11-13; extended support ends 2034-11-14 (offline rule as of $asOf)." }
    if ($Caption -match 'Windows Server 2022') { return "Mainstream support ends 2026-10-13; extended support ends 2031-10-14 (offline rule as of $asOf)." }
    if ($Caption -match 'Windows Server 2019') { return "Mainstream support ended 2024-01-09; extended support ends 2029-01-09. The OS is not yet EOS (offline rule as of $asOf)." }
    if ($Caption -match 'Windows Server 2016') { return "Mainstream support ended 2022-01-11; extended support ends 2027-01-12 (offline rule as of $asOf)." }
    if ($Caption -match 'Windows Server 2012') { return "Standard extended support ended 2023-10-10. ESU enrollment and final eligibility require confirmation (offline rule as of $asOf)." }
    if ($Caption -match 'Windows Server 2008') { return "Standard extended support has ended. ESU history and current support status require confirmation (offline rule as of $asOf)." }
    return "Lifecycle was not resolved by the offline rule set. Validate against the current vendor lifecycle before target selection."
}

function Get-DotNetLifecycleAssessment {
    param([string[]]$Versions)
    $result = @()
    foreach ($version in @($Versions | Sort-Object -Unique)) {
        $major = ""; if ($version -match '^(\d+)\.') { $major = $matches[1] }
        if ($major -eq "6") { $result += (".NET " + $version + " is out of support since 2024-11-12") }
        elseif ($major -eq "7") { $result += (".NET " + $version + " is out of support since 2024-05-14") }
        elseif ($major -eq "8") { $result += (".NET " + $version + " support ends 2026-11-10") }
        elseif ($major -eq "9") { $result += (".NET " + $version + " support ends 2026-11-10") }
        elseif ($major -eq "10") { $result += (".NET " + $version + " LTS support ends 2028-11-14") }
        else { $result += (".NET " + $version + " lifecycle requires current vendor validation") }
    }
    if ($result.Count -eq 0) { return "No dotnet shared runtime was detected; application-local/self-contained runtimes still require validation." }
    return ($result -join "; ") + ". Offline rules are current as of 2026-08-21; verify before approval."
}

function Build-MigrationDecisionData {
    $system = @($script:Data["system"])[0]
    $apps = @($script:Data["iis_applications"])
    $pools = @($script:Data["iis_app_pools"])
    $vdirs = @($script:Data["iis_virtual_directories"])
    $binaries = @($script:Data["application_binaries"])
    $runtimes = @($script:Data["dotnet_runtimes"])
    $configs = @($script:Data["config_metadata"])

    $poolMap = @{}; foreach ($p in $pools) { $poolMap[[string]$p.Name] = $p }
    $poolUseCount = @{}
    foreach ($a in $apps) {
        $poolKey=[string]$a.AppPool
        if (-not $poolUseCount.ContainsKey($poolKey)) { $poolUseCount[$poolKey]=0 }
        $poolUseCount[$poolKey]++
    }
    $physicalMap = @{}; foreach ($v in $vdirs) { $physicalMap[(Normalize-ApplicationName ([string]$v.Application))] = [string]$v.PhysicalPath }
    $binaryMap = @{}
    foreach ($b in $binaries) {
        $key = Normalize-ApplicationName ([string]$b.Application)
        if (-not $binaryMap.ContainsKey($key)) { $binaryMap[$key] = New-Object System.Collections.ArrayList }
        [void]$binaryMap[$key].Add($b)
    }

    $profiles = @()
    foreach ($app in $apps) {
        $key = Normalize-ApplicationName ([string]$app.Name)
        $pool = $null; if ($poolMap.ContainsKey([string]$app.AppPool)) { $pool = $poolMap[[string]$app.AppPool] }
        $appBinaries = @(); if ($binaryMap.ContainsKey($key)) { $appBinaries = @($binaryMap[$key]) }
        $isRoot = ([string]$app.Path -eq "/")
        $isPython = @($appBinaries | Where-Object { $_.Path -match '(?i)(\\\.venv\\|python\d*\.dll|\\site-packages\\)' }).Count -gt 0
        $modernMarkers = @($appBinaries | Where-Object { $_.Path -match '(?i)(Microsoft\.AspNetCore\.|Microsoft\.Extensions\.Hosting\.Abstractions\.dll$)' })
        $isModern = $modernMarkers.Count -gt 0
        $runtimeFamily = "Unknown"; $runtimeEvidence = "No decisive runtime marker"
        $method = "Replatform after confirming runtime, entry point, identity, native dependencies, and source/build availability."
        $confirmation = "Runtime; source/build artifact; business transaction; owner; RTO/RPO"
        $wave = "Wave 3 - Shared or unresolved workloads"
        if ($isRoot) {
            $runtimeFamily = "Mixed/inherited IIS root"
            $runtimeEvidence = "Root application may expose or inherit configuration for child folders"
            $method = "Inventory every active child path and inherited web.config first. Preserve root behavior during initial replatform, then separate active applications from backup/test content."
            $confirmation = "Active child URLs; parent configuration inheritance; content that is backup/test only; authentication; write paths"
            $wave = "Wave 4 - Root site and inherited content"
        } elseif ($isPython) {
            $runtimeFamily = "Python"
            $runtimeEvidence = "Python virtual-environment or site-packages marker detected"
            $method = "Rebuild a pinned Python environment on the target; reproduce IIS/FastCGI or service entry point. Do not treat a copied virtual environment as the authoritative build."
            $confirmation = "Python version; requirements/lock file; entry point; IIS/FastCGI settings; native packages; health endpoint"
            $wave = "Wave 2 - Dedicated framework/Python workloads"
        } elseif ($isModern) {
            $runtimeFamily = "ASP.NET Core / modern .NET"
            $versions = @($modernMarkers | ForEach-Object { $_.ProductVersion } | Where-Object { $_ } | Sort-Object -Unique)
            $runtimeEvidence = "ASP.NET Core/hosting assemblies detected"; if ($versions.Count -gt 0) { $runtimeEvidence += ": " + ($versions -join "; ") }
            $method = "Replatform to supported Windows/IIS and a supported .NET runtime. Prefer upgrade/rebuild from source; allow same-runtime artifact rehost only as a documented, time-boxed exception."
            $confirmation = "Target framework from runtimeconfig.json; hosting model; source/build availability; 32/64-bit; health and transaction tests"
            $wave = "Wave 1 - Dedicated modern workloads"
        } elseif ($pool -and $pool.ManagedRuntimeVersion) {
            $runtimeFamily = ".NET Framework"
            $runtimeEvidence = "IIS pool runtime=" + $pool.ManagedRuntimeVersion + ", pipeline=" + $pool.ManagedPipelineMode
            $method = "Replatform compiled artifacts to supported Windows/IIS with .NET Framework 4.8 where compatible; reproduce IIS modules, ACLs, identity, bitness, and native/provider dependencies before considering refactor."
            $confirmation = "Target framework; app-pool identity; 32-bit flag; native DLL/COM/provider support; authentication; transaction tests"
            $wave = "Wave 2 - Dedicated framework/Python workloads"
        }
        $coupling = "Dedicated app pool"
        if ($poolUseCount.ContainsKey([string]$app.AppPool) -and $poolUseCount[[string]$app.AppPool] -gt 1) {
            $coupling = "Shared app pool with " + $poolUseCount[[string]$app.AppPool] + " applications"
            if (-not $isRoot) { $wave = "Wave 3 - Shared app-pool groups" }
        }
        $profiles += New-Record @{
            Wave=$wave; Application=$app.Name; UrlPath=$app.Path; PhysicalPath=$physicalMap[$key]; AppPool=$app.AppPool
            RuntimeFamily=$runtimeFamily; RuntimeEvidence=$runtimeEvidence; Coupling=$coupling
            SuggestedMethod=$method; RequiresConfirmation=$confirmation
        }
    }
    Export-Records "application_migration_profile" $profiles

    $waveRows = @()
    $waveRows += New-Record @{
        Wave="Wave 0 - Foundation"; Scope="Target Windows/IIS, network, DNS, certificates, monitoring, security agents, backup, deployment and rollback controls"
        Why="All application waves depend on a reproducible and observable landing zone"
        MigrationMethod="Build a parallel supported target; do not clone operational debt blindly. Reproduce required roles/modules, routes, proxy, identities, ACL model and evidence collection."
        EntryCriteria="Cloud landing zone approved; connectivity matrix; target OS/runtime decision; access and change records"
        Test="OS/IIS health; DNS/proxy; inbound/outbound ports; certificate chain; monitoring; backup/restore; time sync; domain/service identity"
        Rollback="No production traffic moved. Correct or rebuild the target; source remains untouched."
    }
    foreach ($waveName in @("Wave 1 - Dedicated modern workloads","Wave 2 - Dedicated framework/Python workloads","Wave 3 - Shared app-pool groups","Wave 4 - Root site and inherited content")) {
        $items = @($profiles | Where-Object { $_.Wave -eq $waveName })
        if ($items.Count -eq 0) { continue }
        $scope = @($items | ForEach-Object { $_.Application }) -join "; "
        $methods = @($items | ForEach-Object { $_.SuggestedMethod } | Sort-Object -Unique) -join " | "
        $waveRows += New-Record @{
            Wave=$waveName; Scope=$scope; Why=(@($items | ForEach-Object {$_.Coupling} | Sort-Object -Unique) -join "; ")
            MigrationMethod=$methods
            EntryCriteria="Owner and criticality confirmed; source/artifact decision; dependencies reachable; baseline transactions captured; data/write-path and rollback authority confirmed"
            Test="Per-application startup, health, authentication, dependency, read/write transaction, file output, logging, error rate, latency and restart/recycle tests"
            Rollback="Withdraw target path/host from traffic; route to preserved source; reconcile writes/files created during the target window before declaring rollback complete"
        }
    }
    Export-Records "migration_waves" $waveRows

    $testRows = @(
        New-Record @{Stage="Baseline";Test="Capture representative URLs, request payload classes, expected status/body/business result, latency, logs and dependency calls on source";PassCriteria="Approved baseline and evidence timestamp exist for every application";Evidence="Test catalog, sanitized request/response fingerprint, source logs and monitoring snapshot"}
        New-Record @{Stage="Build";Test="Validate OS/IIS roles, modules, runtime/hosting bundle, app-pool settings, identity, ACLs, certificates, proxy, DNS and native providers";PassCriteria="Target configuration matches the approved build specification with no unreviewed gaps";Evidence="Build record, configuration export and coverage report"}
        New-Record @{Stage="Deployment";Test="Compare artifact hashes/file counts and verify application startup without configuration or hosting errors";PassCriteria="Expected worker process starts and remains healthy after recycle/reboot";Evidence="Artifact manifest, event logs, IIS logs and process evidence"}
        New-Record @{Stage="Functional";Test="Run health, authentication and one positive/negative business transaction per endpoint class";PassCriteria="Business result and downstream side effects match source";Evidence="Test execution record and application/downstream logs"}
        New-Record @{Stage="Dependency";Test="Exercise database, HTTP/S, proxy, DNS, file, certificate, RPC/COM and external vendor paths";PassCriteria="Every approved dependency succeeds from target and is observable";Evidence="Dependency matrix, firewall evidence and application traces/logs"}
        New-Record @{Stage="Data integrity";Test="Validate read/write consistency, duplicate prevention, retry behavior and local/shared file outputs";PassCriteria="No lost, duplicated or divergent transactions/files";Evidence="Reconciliation report and database/file checks"}
        New-Record @{Stage="Resilience";Test="Recycle app pool, restart service/server where authorized, test dependency timeout and recovery";PassCriteria="Application returns to service within agreed RTO without manual hidden steps";Evidence="Timeline, monitoring alerts and recovery logs"}
        New-Record @{Stage="Performance";Test="Run representative concurrency/volume and compare p50/p95/p99 latency, error rate, CPU, memory, disk and dependency time";PassCriteria="Meets agreed SLO and is not materially worse than approved baseline";Evidence="Load-test and monitoring report"}
        New-Record @{Stage="Cutover smoke";Test="Run synthetic and real approved smoke transactions immediately after traffic switch";PassCriteria="Critical paths pass inside the rollback decision window";Evidence="Cutover checklist, timestamps and transaction identifiers"}
        New-Record @{Stage="Observation";Test="Monitor through peak and batch windows";PassCriteria="No unresolved critical errors, backlog, data mismatch or SLO breach";Evidence="Dashboard/export, event/application logs and owner sign-off"}
    )
    Export-Records "migration_test_plan" $testRows

    $rollbackRows = @(
        New-Record @{Trigger="Critical transaction or authentication failure";Decision="Rollback when the issue cannot be corrected inside the approved decision window";Action="Stop target traffic and restore source route/path/DNS or load-balancer membership";DataProtection="Preserve target logs and transaction IDs; reconcile any accepted writes";Validation="Run source smoke tests and confirm monitoring recovery"}
        New-Record @{Trigger="Error rate, latency or resource use exceeds agreed threshold";Decision="Rollback at the pre-approved threshold, not by ad-hoc judgment during outage";Action="Drain target where possible, return traffic to source and retain target for investigation";DataProtection="Confirm in-flight requests and retry/duplicate behavior";Validation="Source metrics return to baseline and queues/backlogs normalize"}
        New-Record @{Trigger="Database, external API, proxy, certificate or file dependency fails";Decision="Rollback if dependency cannot be restored without configuration risk or deadline breach";Action="Return affected application path or whole coupled app-pool wave to source";DataProtection="Reconcile partial external transactions and files";Validation="End-to-end dependency test passes from source"}
        New-Record @{Trigger="Data inconsistency, duplication or missing output";Decision="Immediately freeze further target writes and invoke application/data owner";Action="Route reads/writes according to the approved consistency runbook; do not blindly switch while dual writes exist";DataProtection="Use transaction reconciliation and an approved restore/replay procedure";Validation="Owner confirms authoritative data state before service resumes"}
        New-Record @{Trigger="Security control, identity or audit failure";Decision="Rollback unless Security explicitly approves a bounded exception";Action="Remove target from service, preserve evidence and restore source path";DataProtection="Preserve audit logs and access evidence";Validation="Security and application owner sign-off"}
    )
    Export-Records "migration_rollback_plan" $rollbackRows

    $runtimeVersions = @($runtimes | ForEach-Object { $_.Version } | Sort-Object -Unique)
    $collectorErrors = @($script:Coverage | Where-Object {$_.Status -eq "ERROR"}).Count
    $capped = @($script:Findings | Where-Object {$_.Code -eq "FILE-INVENTORY-CAPPED"}).Count
    $expired = @($script:Findings | Where-Object {$_.Code -eq "CERT-EXPIRED"}).Count
    $families = @($profiles | ForEach-Object { $_.RuntimeFamily } | Sort-Object -Unique)
    $strategy = "Assess rehost/lift-and-shift feasibility after dependency and vendor validation."
    if ($apps.Count -gt 0 -and $families.Count -gt 1) { $strategy = "Phased replatform by runtime and coupling lane. Build a parallel supported Windows/IIS target, preserve behavior first, and modernize unsupported runtimes separately. Avoid a one-shot refactor or whole-server cutover." }
    elseif ($apps.Count -gt 0) { $strategy = "Parallel replatform to a supported Windows/IIS target, grouped by application pool; refactor only where runtime or vendor compatibility requires it." }
    $confidence = "HIGH for point-in-time inventory"
    if ($collectorErrors -gt 0) { $confidence = "LOW/PARTIAL because one or more collectors failed" }
    elseif ($capped -gt 0 -or $Samples -lt 30) { $confidence = "MEDIUM: inventory or observation-window limitations remain" }
    $summaryRows = @(
        New-Record @{DecisionArea="Preliminary conclusion";Evidence=("{0} IIS applications; {1} app pools; runtime families={2}" -f $apps.Count, $pools.Count, ($families -join ", "));Assessment="Mixed workload with application-pool and root-site coupling";MigrationImpact="Treat this as several application migrations, not one server copy"}
        New-Record @{DecisionArea="Recommended strategy";Evidence="Runtime, pool and binary markers";Assessment=$strategy;MigrationImpact="Use migration waves and an application/path-level rollback boundary where routing permits"}
        New-Record @{DecisionArea="Operating system";Evidence=$system.OSCaption + " build " + $system.BuildNumber;Assessment=(Get-OsLifecycleAssessment $system.OSCaption);MigrationImpact="Select target OS only after application, native provider and cloud-image compatibility tests"}
        New-Record @{DecisionArea=".NET shared runtimes";Evidence=($runtimeVersions -join ", ");Assessment=(Get-DotNetLifecycleAssessment $runtimeVersions);MigrationImpact="Unsupported runtimes require upgrade or a documented time-boxed rehost exception"}
        New-Record @{DecisionArea="Discovery confidence";Evidence=("collectorErrors="+$collectorErrors+", cappedInventories="+$capped+", samples="+$Samples+", intervalSeconds="+$IntervalSeconds);Assessment=$confidence;MigrationImpact="Do not use short samples alone for sizing or dependency sign-off"}
        New-Record @{DecisionArea="Immediate risk review";Evidence=("expiredCertificates="+$expired+", configFiles="+$configs.Count);Assessment="Validate active certificate use, identities, secrets provisioning, external endpoints and root-site child content";MigrationImpact="These items can block startup or business transactions even when artifact copy succeeds"}
        New-Record @{DecisionArea="Mandatory human input";Evidence="Business criticality, owner, RTO/RPO, downtime, source/build availability and transaction acceptance are not machine-discoverable";Assessment="REQUIRES CONFIRMATION";MigrationImpact="Wave order and final go/no-go cannot be approved from technical evidence alone"}
    )
    Export-Records "executive_summary" $summaryRows
}

function Write-HtmlReport {
    $system = @($script:Data["system"])[0]
    $available = @($script:Coverage | Where-Object {$_.Status -eq "AVAILABLE"}).Count
    $errors = @($script:Coverage | Where-Object {$_.Status -eq "ERROR"}).Count
    $high = @($script:Findings | Where-Object {$_.Severity -eq "HIGH"}).Count
    $medium = @($script:Findings | Where-Object {$_.Severity -eq "MEDIUM"}).Count
    $style = @'
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f7fb;color:#1f2937}header{background:#102a43;color:#fff;padding:28px 5%}main{max-width:1400px;margin:auto;padding:24px}.cards{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}.card{background:#fff;border-left:5px solid #2f80ed;border-radius:8px;padding:14px 18px;min-width:150px;box-shadow:0 2px 8px #0001}.card b{font-size:24px;display:block}.warn{border-left-color:#f59e0b}.bad{border-left-color:#dc2626}section{background:#fff;border-radius:8px;padding:18px;margin:16px 0;box-shadow:0 2px 8px #0001}.executive{border-top:6px solid #0f766e}.executive h2{color:#0f5f59}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:8px;border-bottom:1px solid #dce3ea;text-align:left;vertical-align:top;white-space:pre-wrap}th{position:sticky;top:0;background:#eaf0f6}.muted{color:#64748b}.notice{background:#fff7ed;border:1px solid #fdba74;padding:12px;border-radius:8px}.decision-note{background:#ecfeff;border:1px solid #67e8f9;padding:12px;border-radius:8px}code{background:#eef2f7;padding:2px 5px;border-radius:4px}
'@
    $body = New-Object Text.StringBuilder
    [void]$body.Append("<!doctype html><html><head><meta charset='utf-8'><title>WDC Report</title><style>"+$style+"</style></head><body>")
    [void]$body.Append("<header><h1>Windows/.NET Discovery Report</h1><p>Host: " + (ConvertTo-HtmlEncoded $system.ComputerName) + " | Collected: " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz") + " | Tool " + $script:ToolVersion + "</p></header><main>")
    [void]$body.Append("<p class='notice'><b>Security:</b> This report intentionally excludes raw config values and environment-variable values, but paths, topology, accounts, endpoints, and certificate metadata remain sensitive. Protect the entire result package.</p>")
    [void]$body.Append("<div class='cards'><div class='card'><b>"+$available+"</b>collectors available</div><div class='card bad'><b>"+$errors+"</b>collector errors</div><div class='card bad'><b>"+$high+"</b>high findings</div><div class='card warn'><b>"+$medium+"</b>medium findings</div></div>")
    [void]$body.Append("<section class='executive'><h2>Executive Summary and Recommended Migration Direction</h2><p class='decision-note'><b>Decision status:</b> Preliminary technical recommendation generated from discovery evidence. Any item marked REQUIRES CONFIRMATION must be resolved before final wave order, target design, go/no-go, or rollback approval.</p>")
    if ($script:Data.ContainsKey("executive_summary")) {
        $summaryTable = New-HtmlTable "Executive decision summary" @($script:Data["executive_summary"]) 100
        $summaryTable = $summaryTable.Replace("<section>", "<div>").Replace("</section>", "</div>")
        [void]$body.Append($summaryTable)
    }
    [void]$body.Append("</section>")
    foreach ($decisionName in @("migration_waves","application_migration_profile","migration_test_plan","migration_rollback_plan")) {
        if ($script:Data.ContainsKey($decisionName)) { [void]$body.Append((New-HtmlTable $decisionName @($script:Data[$decisionName]) 500)) }
    }
    [void]$body.Append((New-HtmlTable "System summary" @($system) 10))
    [void]$body.Append((New-HtmlTable "Findings" @($script:Findings) 500))
    [void]$body.Append((New-HtmlTable "Collection coverage" @($script:Coverage) 500))
    foreach ($name in @("iis_sites","iis_applications","iis_app_pools","services","scheduled_tasks","dotnet_framework","dotnet_runtimes","dependency_edges","network_connections_aggregate","storage","certificates")) {
        if ($script:Data.ContainsKey($name)) { [void]$body.Append((New-HtmlTable $name @($script:Data[$name]) 200)) }
    }
    [void]$body.Append("<section><h2>Interpretation limits</h2><ul><li>Short performance samples show discovery-time behavior, not authoritative capacity sizing.</li><li>Missing records may mean insufficient privilege or unavailable components; consult Collection coverage.</li><li>Observed network connections are time-bound. Use longer sampling or external dependency mapping for intermittent flows.</li><li>Migration strategy requires application criticality, RTO/RPO, test cases, vendor support, source-code availability, licensing, and business constraints in addition to this evidence.</li></ul></section>")
    [void]$body.Append("</main></body></html>")
    Write-Utf8Text (Join-Path $script:OutputDirectory "report.html") $body.ToString()
}

function ConvertTo-JsonCompat {
    param([object]$Object)
    $cmd = Get-Command ConvertTo-Json -ErrorAction SilentlyContinue
    if ($cmd) { return ($Object | ConvertTo-Json -Depth 6) }
    try {
        [Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions") | Out-Null
        $serializer = New-Object Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = 67108864
        return $serializer.Serialize($Object)
    } catch { return '{"error":"JSON serialization unavailable on this PowerShell/.NET version; use CSV files."}' }
}

function Write-SummaryJson {
    $summary = New-Record @{
        schemaVersion=$script:SchemaVersion; toolVersion=$script:ToolVersion; generatedAt=(Get-Date).ToString("o")
        host=$env:COMPUTERNAME; elevated=$script:IsAdmin; outputDirectory=$script:OutputDirectory
        options=(New-Record @{samples=$Samples;intervalSeconds=$IntervalSeconds;maxFilesPerApp=$MaxFilesPerApp;maxEventRecords=$MaxEventRecords;configMetadata=(-not $SkipConfigMetadata)})
        system=@($script:Data["system"]); findings=@($script:Findings); coverage=@($script:Coverage)
        executiveSummary=@($script:Data["executive_summary"])
        migrationWaves=@($script:Data["migration_waves"])
        applicationMigrationProfile=@($script:Data["application_migration_profile"])
        migrationTestPlan=@($script:Data["migration_test_plan"])
        migrationRollbackPlan=@($script:Data["migration_rollback_plan"])
        recordCounts=(New-Record @{
            services=@($script:Data["services"]).Count;scheduledTasks=@($script:Data["scheduled_tasks"]).Count
            iisApplications=@($script:Data["iis_applications"]).Count;applicationBinaries=@($script:Data["application_binaries"]).Count
            connections=@($script:Data["network_connections_aggregate"]).Count;recentEvents=@($script:Data["recent_events"]).Count
        })
    }
    Write-Utf8Text (Join-Path $script:OutputDirectory "summary.json") (ConvertTo-JsonCompat $summary)
}

function Write-Manifest {
    $manifest = @()
    foreach ($f in @(Get-ChildItem $script:OutputDirectory -Recurse -Force | Where-Object { -not $_.PSIsContainer -and $_.Name -ne "manifest.sha256" })) {
        $relative = $f.FullName.Substring($script:OutputDirectory.Length).TrimStart('\')
        $manifest += ((Get-FileSha256 $f.FullName) + "  " + $relative)
    }
    Write-Utf8Text (Join-Path $script:OutputDirectory "manifest.sha256") ($manifest | Sort-Object)
}

function New-ResultZip {
    if ($NoZip) { return "" }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $zipPath = $script:OutputDirectory.TrimEnd('\') + ".zip"
        if (Test-Path $zipPath) { [IO.File]::Delete($zipPath) }
        [IO.Compression.ZipFile]::CreateFromDirectory($script:OutputDirectory, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $true)
        return $zipPath
    } catch {
        Add-Coverage "result_zip" "UNAVAILABLE" ("ZIP API unavailable: " + $_.Exception.Message + ". Copy the result folder instead.") (Get-Date)
        return ""
    }
}

try {
    Show-Banner
    Write-Host "[WDC] Status: Starting discovery..."
    $script:IsAdmin = Get-IsAdministrator
    if ([string]::IsNullOrEmpty($OutputRoot)) { $OutputRoot = (Get-Location).Path }
    $OutputRoot = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($OutputRoot))
    if (-not (Test-Path $OutputRoot)) { [IO.Directory]::CreateDirectory($OutputRoot) | Out-Null }
    $hostName = ConvertTo-SafeFileName $env:COMPUTERNAME
    $folderName = "wdc-results-" + $hostName + "-" + (Get-Date).ToString("yyyyMMdd-HHmmss")
    $script:OutputDirectory = Join-Path $OutputRoot $folderName
    $script:EvidenceDirectory = Join-Path $script:OutputDirectory "evidence"
    $script:CsvDirectory = Join-Path $script:OutputDirectory "csv"
    [IO.Directory]::CreateDirectory($script:EvidenceDirectory) | Out-Null
    [IO.Directory]::CreateDirectory($script:CsvDirectory) | Out-Null

    Write-Host "[WDC] Output: $script:OutputDirectory"
    Write-Host "[WDC] Elevated: $script:IsAdmin"
    if (-not $script:IsAdmin) { Write-Warning "Not elevated. Collection will continue, but some evidence may be unavailable." }

    Invoke-Collector "system" { Get-SystemInventory }
    Invoke-Collector "storage" { Get-StorageInventory }
    Invoke-Collector "network_configuration" { Get-NetworkInventory }
    Invoke-Collector "installed_software" { Get-InstalledSoftwareInventory }
    Invoke-Collector "hotfixes" { Get-HotfixInventory }
    Invoke-Collector "windows_features" { Get-WindowsFeatureEvidence }
    Invoke-Collector "services" { Get-ServiceInventory }
    Invoke-Collector "processes" { Get-ProcessInventory }
    Invoke-Collector "scheduled_tasks" { Get-ScheduledTaskInventory }
    Invoke-Collector "dotnet" { Get-DotNetInventory }
    Invoke-Collector "certificates" { Get-CertificateInventory }
    Invoke-Collector "local_identities" { Get-LocalIdentityInventory }
    Invoke-Collector "shares" { Get-ShareInventory }
    Invoke-Collector "firewall" { Get-FirewallEvidence }
    Invoke-Collector "msmq" { Get-MsmqInventory }
    if ($NoIis) {
        Write-Host "[WDC] Skipped collector: iis (Skipped by -NoIis)"
        Add-Coverage "iis" "SKIPPED" "Skipped by -NoIis" (Get-Date)
    } elseif (-not (Test-Path (Join-Path $env:WINDIR "System32\inetsrv\appcmd.exe"))) {
        Write-Host "[WDC] IIS was not detected; recording the IIS collector as unavailable."
        foreach ($emptyName in @("iis_sites","iis_applications","iis_virtual_directories","iis_app_pools","application_binaries","config_metadata")) { Export-Records $emptyName @() }
        Add-Coverage "iis" "UNAVAILABLE" "IIS appcmd.exe is not present; IIS 7+ was not detected" (Get-Date)
    } else {
        Invoke-Collector "iis" { Get-IisInventory }
    }
    Invoke-Collector "sampled_telemetry" { Get-SampledTelemetry } -Skip:($NoNetworkSampling -and $NoPerformance) -SkipReason "Both network and performance sampling were disabled"
    Invoke-Collector "event_logs" { Get-RecentEventInventory } -Skip:$NoEventLogs -SkipReason "Skipped by -NoEventLogs"

    if (-not $script:IsAdmin) { Add-Finding "MEDIUM" "COLLECTOR-NOT-ELEVATED" "Collector did not run as administrator" "Some protected paths, process command lines, task data, and logs may be missing." "Re-run from an elevated Command Prompt where authorized and compare coverage."
    }
    Add-Finding "INFO" "PERFORMANCE-SAMPLE-LIMIT" "Performance/network observations are time-bound" ("samples="+$Samples+", intervalSeconds="+$IntervalSeconds) "Collect across business peak, batch window, month-end, and idle periods before capacity sizing or dependency sign-off."
    Write-Host "[WDC] Generating manual context template..."
    Write-ManualContextTemplate
    Invoke-Collector "migration_analysis" { Build-MigrationDecisionData }
    Write-Host "[WDC] Exporting findings and collection coverage..."
    Export-Records "findings" @($script:Findings)
    Export-Records "coverage" @($script:Coverage)
    Write-Host "[WDC] Generating HTML report..."
    Write-HtmlReport
    Write-Host "[WDC] Generating JSON summary..."
    Write-SummaryJson
    Write-Host "[WDC] Generating result manifest..."
    Write-Manifest
    if (-not $NoZip) { Write-Host "[WDC] Creating result ZIP package..." }
    $zipPath = New-ResultZip
    Write-Host "[WDC] Completed: $script:OutputDirectory"
    if ($zipPath) { Write-Host "[WDC] ZIP: $zipPath" }
    $errorCount = @($script:Coverage | Where-Object {$_.Status -eq "ERROR"}).Count
    if ($errorCount -gt 0) { Write-Warning "$errorCount collector(s) reported errors. Review csv\coverage.csv."; exit 2 }
    exit 0
} catch {
    Write-Error (Protect-Text $_.Exception.Message)
    exit 3
}
