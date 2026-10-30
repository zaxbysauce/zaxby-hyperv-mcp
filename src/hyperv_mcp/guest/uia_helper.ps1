# hyperv-mcp in-session UI Automation helper (issue #29, Workstream F PR 5).
#
# Runs in the INTERACTIVE session of the test account (per-user AtLogOn
# scheduled task, LogonType Interactive, RunLevel Highest), hosts
# System.Windows.Automation (in-box UIAutomationClient/UIAutomationTypes)
# and serves one newline-JSON request frame at a time on a local named
# pipe. The pipe is created through the CreateNamedPipeW P/Invoke with
# dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
# PIPE_REJECT_REMOTE_CLIENTS (0x8) - the .NET Framework PipeOptions enum
# names none of the reject-remote bit, so the server is raw handles all
# the way (ConnectNamedPipe / ReadFile / WriteFile / DisconnectNamedPipe
# / CloseHandle). Several instances are served concurrently so read verbs
# do not collide. The host reaches the pipe only through PowerShell
# Direct, as a plain CreateFile client on the same name.
#
# The helper resolves its OWN directory from the script location (the
# HYPERVMCP_HELPER_DIR environment variable is an override only, never
# the primary source) and reads three files the host provisions there:
#   version.txt  the helper version. There is no hardcoded version: if
#                the file is missing or unreadable every request is
#                refused as helper_version_unknown.
#   nonce.txt    the per-install nonce. A request whose nonce is absent
#                or does not equal this file is refused as
#                nonce_mismatch BEFORE any dispatch.
#   uuid.txt     the guest SMBIOS UUID as RECORDED by the host at
#                provision time. target.vm_guid must equal the RECORDED
#                value and the live SMBIOS UUID must match it too, or
#                the request is refused as target_mismatch - fail
#                closed when either side of the comparison is missing.
#
# Security contract:
#   - The pipe DACL (SDDL) grants GENERIC_ALL to LOCAL_SYSTEM,
#     BUILTIN\Administrators and the running user only; the pipe mode
#     rejects remote clients.
#   - Every request frame carries nonce + min_version + target {vm_guid,
#     user_sid, session_id}; the helper enforces them STRICTLY (an
#     unknown version refused as helper_version_unknown; a wrong nonce
#     refused as nonce_mismatch; a stale host refused as
#     helper_version_mismatch; a session-less or mismatched SESSION
#     refused as session_unverified; a mismatched VM/user refused as
#     target_mismatch) BEFORE any verb dispatch. The session dimension
#     must be CONCRETE and equal to this helper's own session for every
#     verb, reads included. Caller text is never evaluated as code:
#     verbs are a closed allowlist driving UIA patterns (Invoke, Toggle,
#     SelectionItem, ExpandCollapse, Value, plus the LegacyIAccessible
#     bridge) - no Invoke-Expression, no ScriptBlock creation from
#     request data, no input injection.
#   - Responses report the length of a set value, never the value; the
#     nonce never appears in a response (minimization); the helper
#     writes no logs.
#
# Windows PowerShell 5.1 only; in-box assemblies; exits when the session
# logs off (the AtLogOn task restarts it on the next logon). The host's
# teardown stops the task and removes the directory: a missing
# version.txt / nonce.txt / uuid.txt is refused with a clear error_class
# on every request, never a terminating crash.

$ErrorActionPreference = 'Stop'

# The helper's own directory: the SCRIPT location is the primary source;
# the env var exists only as an override for local probing.
$HelperDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if ($env:HYPERVMCP_HELPER_DIR) { $HelperDir = $env:HYPERVMCP_HELPER_DIR }

$PipeName = 'hyperv-mcp-uia'
$PipeInstanceCount = 4
# ONE clamp for both tree paths (PRR-117): the host clamps inspect to
# these same bounds (uia.INSPECT_MAX_DEPTH / INSPECT_MAX_ELEMENTS) before
# the request leaves; the ceiling here is defense in depth.
$MaxDepth = 6
$MaxElements = 500
$MaxMatches = 200
$MaxValueChars = 65536
$MaxRequestBytes = 262144
$RequestTimeoutMs = 30000

Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop

Add-Type -Namespace HypervMcp.Uia -Name Native -MemberDefinition @'
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
[DllImport("user32.dll", SetLastError = true)] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool GetUserObjectInformationW(IntPtr hObj, int idx, System.Text.StringBuilder buf, uint len, out uint needed);
[DllImport("user32.dll")] public static extern bool CloseDesktop(IntPtr h);
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("wtsapi32.dll")] public static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out uint bytesReturned);
[DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr buffer);
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern IntPtr CreateNamedPipeW(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool DisconnectNamedPipe(IntPtr hNamedPipe);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool PeekNamedPipe(IntPtr hNamedPipe, IntPtr lpBuffer, uint nBufferSize, out uint lpBytesRead, out uint lpTotalBytesAvail, out uint lpBytesLeftThisMessage);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr hObject);
[DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr hMem);
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string StringSecurityDescriptor, uint StringSDRevision, out IntPtr SecurityDescriptor, IntPtr CreationFlags);
[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
'@

function Read-HelperFile([string]$Name) {
    # Reads the first line of a provisioned file in the helper directory.
    # Returns $null when the directory/file is missing or unreadable (the
    # caller refuses fail closed), '' when the file is empty.
    if ([string]::IsNullOrEmpty($HelperDir)) { return $null }
    try {
        $path = Join-Path $HelperDir $Name
        if (-not (Test-Path -LiteralPath $path)) { return $null }
        $line = Get-Content -LiteralPath $path -TotalCount 1 -ErrorAction Stop
        if ($null -eq $line) { return '' }
        return ([string]$line).Trim()
    } catch {
        return $null
    }
}

function Get-OwnIdentity {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $ownSession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    @{
        sid = $identity.User.Value
        user = ($identity.Name -split '\\')[-1]
        session_id = $ownSession
    }
}

function Get-LiveUuid {
    # The live SMBIOS UUID. $null = the read failed this attempt (not
    # cached, retried on the next request, the request at hand refused
    # fail closed); a string = cached success.
    if ($null -ne $global:LiveUuid) { return $global:LiveUuid }
    $uuid = ''
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
        if ($cs -and $cs.UUID) { $uuid = ([string]$cs.UUID).Trim().ToLowerInvariant() }
    } catch {
        return $null
    }
    if ([string]::IsNullOrEmpty($uuid)) { return $null }
    $global:LiveUuid = $uuid
    return $uuid
}

function Test-OwnsInputDesktop {
    $desk = [HypervMcp.Uia.Native]::OpenInputDesktop(0, $false, 0x0001)
    if ($desk -eq [IntPtr]::Zero) { return $false }
    try {
        $buf = New-Object System.Text.StringBuilder 256
        $needed = 0
        if ([HypervMcp.Uia.Native]::GetUserObjectInformationW($desk, 2, $buf, 256, [ref]$needed)) {
            return ($buf.ToString() -eq 'Default')
        }
        return $false
    } finally { [void][HypervMcp.Uia.Native]::CloseDesktop($desk) }
}

function Get-LockState {
    # WTSQuerySessionInformationW(WTSSessionInfoEx) returns WTSINFOEXW:
    #   Level@0, then WTSINFOEX_LEVEL1 { SessionId@8, State@12,
    #   SessionFlags@16 } - SessionFlags sits at ABSOLUTE offset 16
    #   (a live hexdump confirms it). Values: 0 = locked,
    #   1 = unlocked, INVERTED on Windows 7 / Server 2008 R2 (6.1).
    # Anything unreadable falls back to the input-desktop probe.
    $locked = $null
    $buffer = [IntPtr]::Zero
    $bytes = [uint32]0
    $ok = [HypervMcp.Uia.Native]::WTSQuerySessionInformationW([IntPtr]::Zero, -1, 25, [ref]$buffer, [ref]$bytes)
    if ($ok -and $buffer -ne [IntPtr]::Zero) {
        try {
            $flags = [System.Runtime.InteropServices.Marshal]::ReadInt32($buffer, 16)
            if ($flags -eq 0 -or $flags -eq 1) {
                $v = [Environment]::OSVersion.Version
                $isWin7Or2008R2 = ($v.Major -eq 6 -and $v.Minor -eq 1)
                if ($isWin7Or2008R2) { $locked = ($flags -eq 1) } else { $locked = ($flags -eq 0) }
            }
        } catch {
            $locked = $null
        } finally {
            [void][HypervMcp.Uia.Native]::WTSFreeMemory($buffer)
        }
    }
    if ($null -eq $locked) { $locked = -not (Test-OwnsInputDesktop) }
    return $locked
}

function Get-ForegroundWindow {
    $hWnd = [HypervMcp.Uia.Native]::GetForegroundWindow()
    if ($hWnd -eq [IntPtr]::Zero) { return $null }
    $pidOut = 0
    [void][HypervMcp.Uia.Native]::GetWindowThreadProcessId($hWnd, [ref]$pidOut)
    $title = ''
    $processName = ''
    try {
        $proc = Get-Process -Id $pidOut -ErrorAction Stop
        $processName = $proc.ProcessName
        $title = $proc.MainWindowTitle
    } catch { }
    @{ title = $title; process_name = $processName; pid = $pidOut; hwnd = $hWnd.ToInt64() }
}

function New-PipeSecurity {
    # Fallback DACL (used only when the SDDL conversion is unavailable):
    # current user + BUILTIN\Administrators.
    $security = New-Object System.IO.Pipes.PipeSecurity
    $own = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = New-Object System.IO.Pipes.PipeAccessRule($own, 'ReadWrite', 'Allow')
    $security.AddAccessRule($rule)
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $rule = New-Object System.IO.Pipes.PipeAccessRule($admins, 'ReadWrite', 'Allow')
    $security.AddAccessRule($rule)
    return $security
}

function New-SecurityAttributes([string]$Sddl) {
    # Builds a native SECURITY_ATTRIBUTES for CreateNamedPipeW. Primary
    # path: ConvertStringSecurityDescriptorToSecurityDescriptorW on the
    # SDDL string. Fallback: the .NET PipeSecurity binary descriptor
    # copied into unmanaged memory. Returns $null when both fail (the
    # pipe would then be created with the default DACL).
    $sd = [IntPtr]::Zero
    $ok = $false
    try {
        $ok = [HypervMcp.Uia.Native]::ConvertStringSecurityDescriptorToSecurityDescriptorW($Sddl, 1, [ref]$sd, [IntPtr]::Zero)
    } catch { $ok = $false }
    if ($ok -and $sd -ne [IntPtr]::Zero) {
        $sa = New-Object HypervMcp.Uia.Native+SECURITY_ATTRIBUTES
        $sa.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf([type][HypervMcp.Uia.Native+SECURITY_ATTRIBUTES])
        $sa.lpSecurityDescriptor = $sd
        $sa.bInheritHandle = $false
        return @{ sa = $sa; owner = 'local' }
    }
    $bytes = $null
    try { $bytes = (New-PipeSecurity).GetSecurityDescriptorBinaryForm() } catch { $bytes = $null }
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return $null }
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)
    $sa = New-Object HypervMcp.Uia.Native+SECURITY_ATTRIBUTES
    $sa.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf([type][HypervMcp.Uia.Native+SECURITY_ATTRIBUTES])
    $sa.lpSecurityDescriptor = $ptr
    $sa.bInheritHandle = $false
    return @{ sa = $sa; owner = 'hglobal' }
}

function Free-SecurityAttributes($Sec) {
    # The descriptor is freed AFTER CreateNamedPipeW copied it into the
    # pipe object.
    if ($null -eq $Sec) { return }
    try {
        if ($Sec.owner -eq 'local') {
            [void][HypervMcp.Uia.Native]::LocalFree($Sec.sa.lpSecurityDescriptor)
        } elseif ($Sec.owner -eq 'hglobal') {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Sec.sa.lpSecurityDescriptor)
        }
    } catch { }
}

function New-PipeInstance([int]$UseFirstInstanceFlag) {
    # CreateNamedPipeW('\\.\pipe\hyperv-mcp-uia'):
    #   dwOpenMode = PIPE_ACCESS_DUPLEX (0x3), plus
    #       FILE_FLAG_FIRST_PIPE_INSTANCE (0x00080000) for the very
    #       first instance of this process only - subsequent instances
    #       must not carry it or they would fail against each other.
    #   dwPipeMode  = 0x8 = PIPE_TYPE_BYTE (0x0) | PIPE_READMODE_BYTE
    #       (0x0) | PIPE_WAIT (0x0) | PIPE_REJECT_REMOTE_CLIENTS (0x8)
    #       - compatible with a plain CreateFile client.
    # Returns the handle, or -1 (INVALID_HANDLE_VALUE) on failure.
    $sec = New-SecurityAttributes $PipeSddl
    $handle = [IntPtr](-1)
    try {
        $saPtr = [IntPtr]::Zero
        if ($null -ne $sec) {
            $saPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([type][HypervMcp.Uia.Native+SECURITY_ATTRIBUTES]))
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($sec.sa, $saPtr, $false)
        }
        try {
            $openMode = [uint32]3
            if ($UseFirstInstanceFlag -ne 0) { $openMode = [uint32]($openMode -bor 0x00080000) }
            $handle = [HypervMcp.Uia.Native]::CreateNamedPipeW(('\\.\pipe\' + $PipeName), $openMode, [uint32]8, [uint32]$PipeInstanceCount, [uint32]65536, [uint32]65536, [uint32]0, $saPtr)
        } finally {
            if ($saPtr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($saPtr) }
        }
    } catch {
        $handle = [IntPtr](-1)
    } finally {
        Free-SecurityAttributes $sec
    }
    return $handle
}

function ConvertTo-HashtableDeep($Value) {
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $table = @{}
        foreach ($prop in $Value.PSObject.Properties) { $table[$prop.Name] = ConvertTo-HashtableDeep $prop.Value }
        return $table
    }
    if ($Value -is [System.Array]) {
        $mapped = @()
        foreach ($item in $Value) { $mapped += ,(ConvertTo-HashtableDeep $item) }
        return ,@($mapped)
    }
    return $Value
}

function Get-ElementProcessName($el) {
    # The element's owning process name, lowercase, '.exe' stripped;
    # $null when the process is gone or the property is unreadable.
    # Only successes are cached.
    try { $procId = [int]$el.Current.ProcessId } catch { return $null }
    if (-not $global:ProcNameCache) { $global:ProcNameCache = @{} }
    if ($global:ProcNameCache.ContainsKey($procId)) { return $global:ProcNameCache[$procId] }
    $name = $null
    try { $name = (Get-Process -Id $procId -ErrorAction Stop).ProcessName.ToLowerInvariant() } catch { $name = $null }
    if ($null -ne $name) { $global:ProcNameCache[$procId] = $name }
    return $name
}

function ConvertTo-Condition([hashtable]$selector) {
    # PropertyConditions for the direct property selectors. Returns
    # @{ resolvable = $bool; conditions = <array> }: resolvable $false
    # means a control_type could not be resolved and the caller yields
    # NO MATCH - never everything. (An EMPTY array must not be returned
    # bare: PowerShell collapses it to $null across the call boundary.)
    $conditions = @()
    $direct = @{
        automation_id = [System.Windows.Automation.AutomationElement]::AutomationIdProperty
        name = [System.Windows.Automation.AutomationElement]::NameProperty
        class_name = [System.Windows.Automation.AutomationElement]::ClassNameProperty
    }
    foreach ($key in $direct.Keys) {
        if ($null -ne $selector[$key] -and ([string]$selector[$key]) -ne '') {
            $conditions += (New-Object System.Windows.Automation.PropertyCondition($direct[$key], [string]$selector[$key]))
        }
    }
    if ($null -ne $selector['control_type'] -and ([string]$selector['control_type']) -ne '') {
        $raw = [string]$selector['control_type']
        $ct = $null
        # Resolve a NAME via the static member; LookupById takes Int32
        # and throws on a string, so the numeric id is the fallback only.
        try { $ct = [System.Windows.Automation.ControlType]::$raw } catch { $ct = $null }
        if ($null -eq $ct -and $raw -match '^[0-9]+$') {
            try { $ct = [System.Windows.Automation.ControlType]::LookupById([int]$raw) } catch { $ct = $null }
        }
        if ($null -eq $ct) { return @{ resolvable = $false; conditions = @() } }
        $conditions += (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ct))
    }
    return @{ resolvable = $true; conditions = $conditions }
}

function Find-WindowScope([hashtable]$selector) {
    # The element the search is scoped under: an hwnd, or the first
    # top-level window whose Name equals window_title. $null when an
    # explicit scope matched NOTHING (the whole selector then yields no
    # match - never the desktop root as a fake scope).
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    if ($null -ne $selector['hwnd']) {
        try {
            $byHandle = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr][long]$selector['hwnd'])
            if ($null -ne $byHandle) { return $byHandle }
        } catch { }
        return $null
    }
    if ($selector['window_title']) {
        $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, [string]$selector['window_title'])
        $found = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cond)
        if ($null -ne $found -and $found.Count -gt 0) { return $found[0] }
        return $null
    }
    return $root
}

function Resolve-Target([hashtable]$selector) {
    # Returns the matched elements (an array, possibly empty). An absent
    # selector, an unresolvable condition, or nothing matching yields NO
    # MATCH - never the desktop root element. name_contains is a literal
    # case-insensitive substring and applies TOGETHER with the other
    # conditions; process_name matches the owning process by name.
    $list = @()
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    if ($null -eq $selector) { return $list }
    $scope = Find-WindowScope $selector
    if ($null -eq $scope) { return $list }
    $condResult = ConvertTo-Condition $selector
    if ($null -ne $condResult -and -not $condResult.resolvable) { return $list }
    $conditions = @()
    if ($null -ne $condResult) { $conditions = @($condResult.conditions) }
    $nameNeedle = $null
    if ($null -ne $selector['name_contains'] -and ([string]$selector['name_contains']) -ne '') { $nameNeedle = [string]$selector['name_contains'] }
    $procNeedle = $null
    if ($null -ne $selector['process_name'] -and ([string]$selector['process_name']) -ne '') {
        $procNeedle = ([string]$selector['process_name']).Trim().ToLowerInvariant() -replace '\.exe$', ''
    }
    if ($conditions.Count -eq 0 -and $null -eq $nameNeedle -and $null -eq $procNeedle) {
        # No match condition at all: only an explicitly scoped window
        # (hwnd / window_title) is itself a match.
        if (-not [object]::ReferenceEquals($scope, $root)) { $list += $scope }
        return $list
    }
    $cond = [System.Windows.Automation.Condition]::TrueCondition
    if ($conditions.Count -eq 1) {
        # AndCondition requires at least two conditions.
        $cond = $conditions[0]
    } elseif ($conditions.Count -gt 1) {
        $cond = New-Object System.Windows.Automation.AndCondition($conditions)
    }
    $found = $scope.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
    foreach ($el in $found) {
        if ($list.Count -ge $MaxMatches) { break }
        if ($null -ne $nameNeedle) {
            $nm = $null
            try { $nm = [string]$el.Current.Name } catch { $nm = $null }
            if ($null -eq $nm) { continue }
            if ($nm.IndexOf($nameNeedle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        }
        if ($null -ne $procNeedle) {
            $pn = Get-ElementProcessName $el
            if ($null -eq $pn -or $pn -ne $procNeedle) { continue }
        }
        $list += $el
    }
    return $list
}

function Select-One($elements, [hashtable]$selector) {
    if ($null -eq $elements -or $elements.Count -eq 0) { return $null }
    if ($null -ne $selector['index']) {
        $idx = [int]$selector['index']
        if ($idx -lt 0 -or $idx -ge $elements.Count) { return $null }
        return $elements[$idx]
    }
    if ($elements.Count -gt 1) {
        $candidates = @()
        $i = 0
        foreach ($el in $elements) {
            if ($i -ge 20) { break }
            $rect = ''
            try { $r = $el.Current.BoundingRectangle; $rect = '{0},{1},{2},{3}' -f [int]$r.X, [int]$r.Y, [int]$r.Width, [int]$r.Height } catch { }
            $candidates += @{ selector = $selector; name = [string]$el.Current.Name; control_type = [string]$el.Current.ControlType.ProgrammaticName; rect = $rect }
            $i++
        }
        return @{ ambiguous = $true; candidates = $candidates }
    }
    return $elements[0]
}

function Get-ElementResult($el) {
    $rect = ''
    try { $r = $el.Current.BoundingRectangle; $rect = '{0},{1},{2},{3}' -f [int]$r.X, [int]$r.Y, [int]$r.Width, [int]$r.Height } catch { }
    $runtimeId = @()
    try { $runtimeId = @($el.GetRuntimeId()) } catch { }
    $focusable = $false
    try { $focusable = [bool]$el.Current.IsKeyboardFocusable } catch { $focusable = $false }
    $offscreen = $false
    try { $offscreen = [bool]$el.Current.IsOffscreen } catch { $offscreen = $false }
    $patterns = @()
    try {
        $patterns = @($el.GetSupportedPatterns() | ForEach-Object { (($_.ProgrammaticName -replace 'Identifiers\.Pattern$', '') -replace 'Pattern$', '') })
    } catch { $patterns = @() }
    @{
        element_id = ($runtimeId -join ':')
        name = [string]$el.Current.Name
        control_type = [string]$el.Current.ControlType.ProgrammaticName -replace '^ControlType\.', ''
        automation_id = [string]$el.Current.AutomationId
        class_name = [string]$el.Current.ClassName
        enabled = [bool]$el.Current.IsEnabled
        keyboard_focusable = $focusable
        offscreen = $offscreen
        patterns = $patterns
        rect = $rect
    }
}

function Walk-Tree($el, $d, $cap, [ref]$seen) {
    if ($seen.Value -ge $cap -or $d -lt 0) { return $null }
    $seen.Value = $seen.Value + 1
    $node = Get-ElementResult $el
    $children = New-Object System.Collections.Generic.List[object]
    if ($d -gt 0) {
        $kids = $null
        try { $kids = $el.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition) } catch { $kids = $null }
        if ($null -ne $kids) {
            foreach ($k in $kids) {
                if ($seen.Value -ge $cap) { break }
                $child = Walk-Tree $k ($d - 1) $cap $seen
                if ($null -ne $child) { [void]$children.Add($child) }
            }
        }
    }
    # NB: '@()' around a List[object] throws on PS 5.1 (build-dependent
    # "Argument types do not match") - the bracket setter plus ToArray()
    # is the safe shape.
    $node['children'] = $children.ToArray()
    return $node
}

function Invoke-Pattern($el, $automationPattern, [string]$action, $argument) {
    $pattern = $null
    try { $pattern = $el.GetCurrentPattern($automationPattern) } catch { return $null }
    if ($null -eq $pattern) { return $null }
    try {
        switch ($action) {
            'invoke' { [void]$pattern.Invoke() }
            'toggle' { [void]$pattern.Toggle() }
            'select' { [void]$pattern.Select() }
            'expand' { [void]$pattern.Expand() }
            'collapse' { [void]$pattern.Collapse() }
            'setvalue' { $pattern.SetValue([string]$argument) }
            default { return $null }
        }
    } catch {
        return $null
    }
    return $true
}

function Invoke-Request([hashtable]$req) {
    $verb = [string]$req['verb']

    # version.txt is the ONLY source of the helper's version.
    if ([string]::IsNullOrEmpty($HelperVersion)) {
        return @{ ok = $false; error_class = 'helper_version_unknown'; error = 'version.txt is missing or unreadable in the helper directory; the helper refuses to serve' }
    }

    # The nonce check runs BEFORE any dispatch: the request must carry
    # the per-install nonce verbatim. A missing nonce.txt also lands
    # here (fail closed on the install dimension).
    if ([string]::IsNullOrEmpty($ownNonce) -or -not $req.ContainsKey('nonce') -or $null -eq $req['nonce'] -or ([string]$req['nonce']).Trim() -ne $ownNonce) {
        return @{ ok = $false; error_class = 'nonce_mismatch'; error = 'the request nonce does not match this install (nonce.txt)' }
    }

    if ($req.ContainsKey('min_version') -and $null -ne $req['min_version'] -and ([string]$req['min_version']) -ne $HelperVersion) {
        return @{ ok = $false; error_class = 'helper_version_mismatch'; error = "helper version $HelperVersion cannot serve min_version $($req['min_version'])" }
    }

    $target = $req['target']
    if ($null -eq $target -or $target -isnot [hashtable]) {
        return @{ ok = $false; error_class = 'session_unverified'; error = 'the request carries no target' }
    }

    # The VM-identity dimension speaks the RECORDED SMBIOS UUID (the
    # host records it at provision time and echoes it in target.vm_guid)
    # and FAILS CLOSED: a missing uuid.txt, a mismatched request value,
    # or a live SMBIOS UUID that differs from the recording all refuse.
    if ([string]::IsNullOrEmpty($recordedUuid)) {
        return @{ ok = $false; error_class = 'target_mismatch'; error = 'the recorded VM identity (uuid.txt) is missing; the helper refuses fail closed' }
    }
    $reqGuid = ''
    if ($null -ne $target['vm_guid']) { $reqGuid = ([string]$target['vm_guid']).Trim().ToLowerInvariant() }
    if ($reqGuid -ne $recordedUuid) {
        return @{ ok = $false; error_class = 'target_mismatch'; error = 'the request targets a different VM identity than this helper was provisioned for' }
    }
    $liveUuid = Get-LiveUuid
    if ([string]::IsNullOrEmpty($liveUuid) -or $liveUuid -ne $recordedUuid) {
        return @{ ok = $false; error_class = 'target_mismatch'; error = 'the live SMBIOS UUID does not match the recorded identity; the helper refuses fail closed' }
    }

    if ($null -ne $target['user_sid'] -and ([string]$target['user_sid']) -ne $identity.sid) {
        return @{ ok = $false; error_class = 'target_mismatch'; error = "the request targets user $($target['user_sid']) but this helper runs as $($identity.sid)" }
    }

    # The session dimension must be CONCRETE and equal to this helper's
    # own session for EVERY verb, reads included.
    if ($null -eq $target['session_id'] -or ([int]$target['session_id']) -ne $identity.session_id) {
        return @{ ok = $false; error_class = 'session_unverified'; error = "the request does not carry this helper's interactive session ($($identity.session_id))" }
    }

    $locked = Get-LockState

    if ($verb -eq 'session_state') {
        return @{
            ok = $true
            result = @{
                active_session_id = $identity.session_id
                interactive_user = $identity.user
                locked = $locked
                foreground_window = (Get-ForegroundWindow)
            }
        }
    }

    $selector = $req['selector']
    if ($null -eq $selector -and $req.ContainsKey('args') -and $null -ne $req['args'] -and $req['args'] -is [hashtable]) {
        $selector = $req['args']['selector']
    }
    if ($null -ne $selector -and $selector -isnot [hashtable]) { $selector = $null }

    if ($verb -eq 'inspect') {
        $depth = 3; $cap = 200
        if ($null -ne $req['args'] -and $req['args'] -is [hashtable]) {
            if ($null -ne $req['args']['depth']) { $depth = [Math]::Min([int]$req['args']['depth'], $MaxDepth) }
            if ($null -ne $req['args']['max_elements']) { $cap = [Math]::Min([int]$req['args']['max_elements'], $MaxElements) }
        }
        # inspect HONOURS the selector it is given: the walk is scoped to
        # the matched element; no match (or an ambiguous one) yields an
        # empty tree, never a walk of the whole desktop by accident.
        $startEl = [System.Windows.Automation.AutomationElement]::RootElement
        if ($null -ne $selector) {
            $elements = @(Resolve-Target $selector)
            if ($elements.Count -eq 0) {
                return @{ ok = $true; result = @{ elements = 0; truncated = $false; tree = $null } }
            }
            $one = Select-One $elements $selector
            if ($null -ne $one -and $one.ambiguous) {
                return @{ ok = $false; error_class = 'ambiguous_selector'; error = 'the selector matched more than one element'; candidates = $one.candidates }
            }
            if ($null -eq $one) {
                return @{ ok = $true; result = @{ elements = 0; truncated = $false; tree = $null } }
            }
            $startEl = $one
        }
        $seen = 0
        $tree = Walk-Tree $startEl $depth $cap ([ref]$seen)
        return @{ ok = $true; result = @{ elements = $seen; truncated = ($seen -ge $cap); tree = $tree } }
    }

    if ($verb -eq 'find' -or $verb -eq 'wait_for') {
        $elements = @(Resolve-Target $selector)
        if ($verb -eq 'wait_for') {
            $argsPair = $req['args']
            $gone = $false; $budget = 30
            if ($null -ne $argsPair -and $argsPair -is [hashtable]) {
                if ($null -ne $argsPair['gone']) { $gone = [bool]$argsPair['gone'] }
                if ($null -ne $argsPair['timeout_s']) { $budget = [Math]::Min([int]$argsPair['timeout_s'], 120) }
            }
            $deadline = [DateTime]::UtcNow.AddSeconds($budget)
            while ([DateTime]::UtcNow -lt $deadline) {
                $elements = @(Resolve-Target $selector)
                $present = ($null -ne $elements -and $elements.Count -gt 0)
                if ($gone -and -not $present) { return @{ ok = $true; result = @{ gone = $true } } }
                if (-not $gone -and $present) { break }
                Start-Sleep -Milliseconds 400
            }
        }
        if ($req.ContainsKey('element_id') -and $null -ne $req['element_id']) {
            # element_id IS a UIA RuntimeId: resolve the live element by it,
            # exactly as the mutating path does. An unresolvable id answers
            # like a selector no-match (an empty element list), which is
            # the find verb's contract; the mutating verbs refuse an
            # unknown id with element_not_found.
            $idWanted = [string]$req['element_id']
            $elements = @()
            $scan = [System.Windows.Automation.AutomationElement]::RootElement.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
            foreach ($candidate in $scan) {
                $rid = ''
                try { $rid = (@($candidate.GetRuntimeId()) -join ':') } catch { }
                if ($rid -eq $idWanted) { $elements = @($candidate); break }
            }
        }
        if ($null -eq $elements -or $elements.Count -eq 0) {
            return @{ ok = $true; result = @{ elements = @() } }
        }
        $one = Select-One $elements $selector
        if ($null -ne $one -and $one.ambiguous) {
            return @{ ok = $false; error_class = 'ambiguous_selector'; error = 'the selector matched more than one element'; candidates = $one.candidates }
        }
        return @{ ok = $true; result = @{ elements = @(Get-ElementResult $one) } }
    }

    $elementIdWanted = $null
    if ($req.ContainsKey('element_id')) { $elementIdWanted = [string]$req['element_id'] }
    elseif ($null -ne $req['args'] -and $req['args'] -is [hashtable] -and $null -ne $req['args']['element_id']) { $elementIdWanted = [string]$req['args']['element_id'] }

    $el = $null
    if ($elementIdWanted) {
        $all = [System.Windows.Automation.AutomationElement]::RootElement.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($candidate in $all) {
            $rid = ''
            try { $rid = (@($candidate.GetRuntimeId()) -join ':') } catch { }
            if ($rid -eq $elementIdWanted) { $el = $candidate; break }
        }
        if ($null -eq $el) {
            return @{ ok = $false; error_class = 'element_not_found'; error = "no live element matches element_id $elementIdWanted" }
        }
    } else {
        $elements = @(Resolve-Target $selector)
        $one = Select-One $elements $selector
        if ($null -ne $one -and $one.ambiguous) {
            return @{ ok = $false; error_class = 'ambiguous_selector'; error = 'the selector matched more than one element'; candidates = $one.candidates }
        }
        $el = $one
        if ($null -eq $el) {
            return @{ ok = $false; error_class = 'element_not_found'; error = 'the selector resolved no element' }
        }
    }

    # Every mutating verb consults the lock state: the console can still
    # drive a locked Default desktop, so mutating silently would be wrong.
    if ($verb -eq 'focus' -or $verb -eq 'invoke' -or $verb -eq 'set_value') {
        if ($locked -or -not (Test-OwnsInputDesktop)) {
            return @{ ok = $false; error_class = 'no_interactive_desktop'; error = 'the session is locked; this verb needs the interactive desktop' }
        }
    }

    if ($verb -eq 'focus') {
        # VERIFY the focus instead of asserting it, and report whether the
        # best-effort window raise succeeded rather than discarding it.
        try { $el.SetFocus() } catch { }
        $focused = $false
        try { $focused = [bool]$el.Current.HasKeyboardFocus } catch { $focused = $false }
        $raised = $false
        try {
            $hWnd = [IntPtr]$el.Current.NativeWindowHandle
            if ($hWnd -ne [IntPtr]::Zero) { $raised = [bool][HypervMcp.Uia.Native]::SetForegroundWindow($hWnd) }
        } catch { $raised = $false }
        return @{ ok = $true; result = @{ focused = $focused; raised = $raised } }
    }

    if ($verb -eq 'set_value') {
        $value = $null
        if ($req.ContainsKey('value')) { $value = $req['value'] }
        elseif ($null -ne $req['args'] -and $req['args'] -is [hashtable]) { $value = $req['args']['value'] }
        if ($null -eq $value) {
            return @{ ok = $false; error_class = 'invalid_request'; error = 'set_value requires a value' }
        }
        $text = [string]$value
        if ($text.Length -gt $MaxValueChars) {
            return @{ ok = $false; error_class = 'invalid_request'; error = 'the value exceeds the 64 KiB bound' }
        }
        $fired = $null
        if ($null -ne (Invoke-Pattern $el ([System.Windows.Automation.ValuePattern]::Pattern) 'setvalue' $text)) {
            $fired = 'Value'
        } else {
            # msaa bridge: the UIA MSAA proxy exposes LegacyIAccessiblePattern
            # for legacy/VB-style controls that carry no UIA Value pattern.
            # $legacyPattern is probed ONCE at startup: the in-box .NET
            # Framework UIA wrapper ships no managed
            # LegacyIAccessiblePattern type, and a per-request type
            # literal would throw inside this verb and silently disable
            # the bridge - where the type does not exist the branch is
            # skipped cleanly instead.
            $legacy = $null
            if ($null -ne $legacyPattern) {
                try { $legacy = $el.GetCurrentPattern($legacyPattern) } catch { $legacy = $null }
            }
            if ($null -ne $legacy) {
                try { $legacy.SetValue($text); $fired = 'LegacyIAccessible' } catch { $fired = $null }
            }
        }
        if ($null -eq $fired) {
            return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes no ValuePattern or the msaa LegacyIAccessible bridge' }
        }
        return @{ ok = $true; result = @{ length = $text.Length; length_set = $text.Length; pattern = $fired } }
    }

    if ($verb -eq 'invoke') {
        # Report WHICH pattern fired; the unsupported refusal names every
        # pattern that was tried (the msaa LegacyIAccessible bridge rides
        # here too, via DoDefaultAction).
        $fired = $null
        if ($null -ne (Invoke-Pattern $el ([System.Windows.Automation.InvokePattern]::Pattern) 'invoke' $null)) { $fired = 'Invoke' }
        if ($null -eq $fired -and $null -ne (Invoke-Pattern $el ([System.Windows.Automation.TogglePattern]::Pattern) 'toggle' $null)) { $fired = 'Toggle' }
        if ($null -eq $fired -and $null -ne (Invoke-Pattern $el ([System.Windows.Automation.SelectionItemPattern]::Pattern) 'select' $null)) { $fired = 'SelectionItem' }
        if ($null -eq $fired -and $null -ne (Invoke-Pattern $el ([System.Windows.Automation.ExpandCollapsePattern]::Pattern) 'expand' $null)) { $fired = 'ExpandCollapse' }
        if ($null -eq $fired) {
            # The msaa LegacyIAccessible bridge rides here too, via
            # DoDefaultAction - guarded by the startup-probed pattern
            # object (see the set_value leg for why it is probed, not
            # spelled as a per-request type literal).
            $legacy = $null
            if ($null -ne $legacyPattern) {
                try { $legacy = $el.GetCurrentPattern($legacyPattern) } catch { $legacy = $null }
            }
            if ($null -ne $legacy) {
                try { $legacy.DoDefaultAction(); $fired = 'LegacyIAccessible' } catch { $fired = $null }
            }
        }
        if ($null -eq $fired) {
            return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes none of the tried patterns: Invoke, Toggle, SelectionItem, ExpandCollapse, LegacyIAccessible (msaa bridge)' }
        }
        return @{ ok = $true; result = @{ invoked = $true; pattern = $fired } }
    }

    return @{ ok = $false; error_class = 'invalid_request'; error = "unknown verb $verb" }
}

# ---------------------------------------------------------------------------
# startup: identity, provisioned files, self hash, then the serve loop
# ---------------------------------------------------------------------------

$HelperVersion = Read-HelperFile 'version.txt'
if ($null -eq $HelperVersion) { $HelperVersion = '' }
$ownNonce = Read-HelperFile 'nonce.txt'
if ($null -eq $ownNonce) { $ownNonce = '' }
$recordedUuid = Read-HelperFile 'uuid.txt'
if ($null -eq $recordedUuid -or $recordedUuid -eq '') { $recordedUuid = '' } else { $recordedUuid = $recordedUuid.ToLowerInvariant() }
$identity = Get-OwnIdentity
$capabilities = @('uia', 'msaa')
$ownSha256 = ''
try {
    $selfPath = $MyInvocation.MyCommand.Path
    if (-not $selfPath -and $HelperDir) { $selfPath = Join-Path $HelperDir 'uia_helper.ps1' }
    if ($selfPath) {
        $ownSha256 = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($selfPath))) -replace '-', ''
    }
} catch { $ownSha256 = '' }

# The msaa bridge pattern object, probed ONCE (PRR-112): the in-box .NET
# Framework UIA wrapper ships no managed LegacyIAccessiblePattern type, so
# a per-request type literal throws inside the verb and its catch silently
# disables the bridge. Where the type exists the bridge is live; where it
# does not the legacy fallback is skipped cleanly.
$legacyPattern = $null
try { $legacyPattern = [System.Windows.Automation.LegacyIAccessiblePattern]::Pattern } catch { $legacyPattern = $null }

# The pipe DACL: GENERIC_ALL for LOCAL_SYSTEM, BUILTIN\Administrators and
# the running user (the existing New-PipeSecurity intent), expressed as
# SDDL for the native path with the .NET ACL as fallback.
$PipeSddl = 'D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;' + $identity.sid + ')'

function Get-SessionBlock {
    # Lock state is computed per RESPONSE: a session locked after this
    # helper started must be reported locked on every answer. The nonce
    # deliberately does NOT appear here (minimization).
    return @{
        session_id = $identity.session_id
        interactive_user = $identity.user
        locked = (Get-LockState)
        helper = @{ running = $true; version = $HelperVersion; capabilities = $capabilities; sha256 = $ownSha256 }
    }
}

# One serve loop per pipe instance, each on its own runspace so several
# clients can be handled concurrently. The loop body never leaves the
# client hanging: on every failure path the instance is disconnected,
# closed and recreated, and a persistent failure sleeps 250 ms per
# attempt so it cannot hot-spin (the helper writes no logs).
$workerScript = @'
param([IntPtr]$Handle)
$serve = $Handle
while ($true) {
    $handle = $serve
    try {
        if ($handle -eq [IntPtr]::Zero -or $handle.ToInt64() -eq -1) { throw 'invalid pipe handle' }
        $connected = [HypervMcp.Uia.Native]::ConnectNamedPipe($handle, [IntPtr]::Zero)
        if (-not $connected) {
            $cerr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($cerr -ne 535) { throw "ConnectNamedPipe error $cerr" }
        }
        $deadline = [DateTime]::UtcNow.AddMilliseconds($RequestTimeoutMs)
        $acc = New-Object System.Collections.Generic.List[byte]
        $buf = New-Object byte[] 4096
        $line = $null
        while ($null -eq $line) {
            if ([DateTime]::UtcNow -ge $deadline) { break }
            $read = [uint32]0; $avail = [uint32]0; $left = [uint32]0
            if (-not [HypervMcp.Uia.Native]::PeekNamedPipe($handle, [IntPtr]::Zero, 0, [ref]$read, [ref]$avail, [ref]$left)) { break }
            if ($avail -eq 0) { Start-Sleep -Milliseconds 50; continue }
            $want = [uint32][Math]::Min([int]$avail, $buf.Length)
            $got = [uint32]0
            if (-not [HypervMcp.Uia.Native]::ReadFile($handle, $buf, $want, [ref]$got, [IntPtr]::Zero)) { break }
            if ($got -eq 0) { break }
            for ($i = 0; $i -lt $got; $i++) {
                if ($buf[$i] -eq 10) { $line = [System.Text.Encoding]::UTF8.GetString($acc.ToArray()); break }
                [void]$acc.Add($buf[$i])
            }
            if ($acc.Count -gt $MaxRequestBytes) { break }
        }
        if ($null -ne $line) {
            $line = $line.TrimEnd("`r")
            $response = $null
            $requestId = ''
            $req = @{}
            try {
                $parsed = ConvertTo-HashtableDeep ($line | ConvertFrom-Json)
                if ($parsed -is [hashtable]) { $req = $parsed }
                if ($req.ContainsKey('id')) { $requestId = [string]$req['id'] }
            } catch {
                $req = @{}
            }
            # F12: the verb dispatch runs in a FRESH child runspace per
            # request, polled against its own deadline. The request-read
            # budget above bounds only the READ; without this second
            # budget a hung UIA call (a wedged target app is a common UIA
            # failure) would wedge this pipe instance forever - four
            # hangs would exhaust every instance. The child receives ONLY
            # the parsed request hashtable, never the raw client stream;
            # this runspace keeps sole ownership of the pipe handle.
            $dispatchDeadline = [DateTime]::UtcNow.AddMilliseconds($RequestTimeoutMs)
            $childRunspace = $null
            $childShell = $null
            $childAsync = $null
            $abandoned = $false
            try {
                $childRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($sessionState)
                $childRunspace.Open()
                $childShell = [System.Management.Automation.PowerShell]::Create()
                $childShell.Runspace = $childRunspace
                [void]$childShell.AddScript('param([hashtable]$Request) Invoke-Request $Request').AddArgument($req)
                $childAsync = $childShell.BeginInvoke()
                while (-not $childAsync.IsCompleted) {
                    if ([DateTime]::UtcNow -ge $dispatchDeadline) { break }
                    Start-Sleep -Milliseconds 50
                }
                if ($childAsync.IsCompleted) {
                    $response = $childShell.EndInvoke($childAsync)
                } else {
                    # Answer from THIS runspace, which still owns the pipe:
                    # the wedged call leaks its thread (BeginStop is a
                    # best-effort asynchronous stop; Close/Dispose can
                    # block on a busy runspace), never a pipe instance.
                    $abandoned = $true
                    try { [void]$childShell.BeginStop($null, $null) } catch { }
                    $response = @{ ok = $false; error_class = 'dispatch_timeout'; error = "the verb dispatch did not complete within the $($RequestTimeoutMs) ms per-request deadline and was abandoned" }
                }
            } catch {
                $response = @{ ok = $false; error_class = 'helper_error'; error = $_.Exception.Message }
            }
            if ($null -eq $response) { $response = @{ ok = $false; error_class = 'helper_error'; error = 'the verb produced no response' } }
            # EndInvoke yields the child's output as a PSDataCollection, not
            # the response object itself: unwrap the single element before
            # the id/session attaches, which must land on the hashtable. A
            # property set on the collection throws and the tolerant catch
            # would silently ship the frame without either key.
            if ($response -isnot [string] -and $response -isnot [System.Collections.IDictionary] -and $response -is [System.Collections.IEnumerable]) {
                $collected = @($response)
                if ($collected.Count -ge 1) { $response = $collected[0] }
            }
            try { $response.id = $requestId } catch { }
            try { $response.session = Get-SessionBlock } catch { }
            $json = ''
            try { $json = ($response | ConvertTo-Json -Compress -Depth 16) } catch { $json = '{"id":"","ok":false,"error_class":"helper_error","error":"response serialization failed"}' }
            $payload = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
            $written = [uint32]0
            [void][HypervMcp.Uia.Native]::WriteFile($handle, $payload, [uint32]$payload.Length, [ref]$written, [IntPtr]::Zero)
            if (-not $abandoned) {
                if ($null -ne $childShell) { try { $childShell.Dispose() } catch { } }
                if ($null -ne $childRunspace) { try { $childRunspace.Dispose() } catch { } }
            } elseif ($null -ne $childRunspace) {
                # Non-blocking close request for the abandoned runspace;
                # the client already holds its error frame and the accept
                # loop below recycles this instance either way.
                try { $childRunspace.CloseAsync() } catch { }
            }
        }
    } catch {
        Start-Sleep -Milliseconds 250
    } finally {
        if ($handle -ne [IntPtr]::Zero -and $handle.ToInt64() -ne -1) {
            try { [void][HypervMcp.Uia.Native]::DisconnectNamedPipe($handle) } catch { }
            try { [void][HypervMcp.Uia.Native]::CloseHandle($handle) } catch { }
        }
    }
    $next = [IntPtr](-1)
    try { $next = New-PipeInstance 0 } catch { $next = [IntPtr](-1) }
    while ($next.ToInt64() -eq -1) {
        Start-Sleep -Milliseconds 250
        try { $next = New-PipeInstance 0 } catch { $next = [IntPtr](-1) }
    }
    $serve = $next
}
'@

$functionNames = @(
    'Read-HelperFile', 'Get-OwnIdentity', 'Get-LiveUuid', 'Test-OwnsInputDesktop',
    'Get-LockState', 'Get-ForegroundWindow', 'New-PipeSecurity', 'New-SecurityAttributes',
    'Free-SecurityAttributes', 'New-PipeInstance', 'ConvertTo-HashtableDeep',
    'Get-ElementProcessName', 'ConvertTo-Condition', 'Find-WindowScope', 'Resolve-Target',
    'Select-One', 'Get-ElementResult', 'Walk-Tree', 'Invoke-Pattern', 'Invoke-Request',
    'Get-SessionBlock'
)
$sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
foreach ($name in $functionNames) {
    $cmd = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        $sessionState.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($name, $cmd.Definition)))
    }
}
$sessionVariables = @{
    HelperDir = $HelperDir
    HelperVersion = $HelperVersion
    ownNonce = $ownNonce
    recordedUuid = $recordedUuid
    capabilities = $capabilities
    ownSha256 = $ownSha256
    identity = $identity
    PipeName = $PipeName
    PipeInstanceCount = $PipeInstanceCount
    MaxDepth = $MaxDepth
    MaxElements = $MaxElements
    MaxMatches = $MaxMatches
    MaxValueChars = $MaxValueChars
    MaxRequestBytes = $MaxRequestBytes
    RequestTimeoutMs = $RequestTimeoutMs
    PipeSddl = $PipeSddl
    legacyPattern = $legacyPattern
    # The template itself, so each worker's per-request child runspace
    # (the F12 dispatch bound) is built from the same session state.
    sessionState = $sessionState
}
foreach ($key in @($sessionVariables.Keys)) {
    $sessionState.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($key, $sessionVariables[$key], 'helper state')))
}

# Create the initial instances INSIDE the loop guard: instance 0 carries
# FILE_FLAG_FIRST_PIPE_INSTANCE (only one creator may hold it; it fails
# while any other process holds the name, and is retried cold until the
# previous helper exits); the rest are plain duplex instances.
$initialHandles = @()
for ($i = 0; $i -lt $PipeInstanceCount; $i++) {
    $h = [IntPtr](-1)
    while ($h.ToInt64() -eq -1) {
        $h = New-PipeInstance ($i -eq 0)
        if ($h.ToInt64() -eq -1) { Start-Sleep -Milliseconds 250 }
    }
    $initialHandles += $h
}

$script:Workers = @()
for ($i = 0; $i -lt $initialHandles.Count; $i++) {
    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($sessionState)
    $runspace.Open()
    $shell = [System.Management.Automation.PowerShell]::Create()
    $shell.Runspace = $runspace
    [void]$shell.AddScript($workerScript).AddArgument($initialHandles[$i])
    [void]$shell.BeginInvoke()
    $script:Workers += $shell
}

# The engine thread only babysits the workers; the task stops the whole
# process at logoff or teardown.
while ($true) { Start-Sleep -Seconds 30 }
