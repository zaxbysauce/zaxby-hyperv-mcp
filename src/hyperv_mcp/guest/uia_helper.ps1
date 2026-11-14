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
# ONE clamp for both tree paths (PRR-117, extended by issue #136): the host
# clamps inspect to these same bounds (uia.INSPECT_MAX_DEPTH /
# INSPECT_MAX_ELEMENTS) before the request leaves; the ceiling here is
# defense in depth. Depth 32: the Electron/Chromium accessibility tree
# lives deeper than the old 6 (#136 AC9 records the depth actually needed).
$MaxDepth = 32
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
[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
[DllImport("user32.dll")] public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr dpiContext);
[DllImport("shcore.dll")] public static extern int SetProcessDpiAwareness(int value);
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

function Get-WindowScopeSet([hashtable]$selector) {
    if ($null -eq $selector) { $selector = @{} }
    # Issue #136 scope model: returns the ARRAY of elements a search is
    # scoped under. NOTHING here ever returns the desktop root element as
    # a search root - a selector with no window scope resolves to the
    # FOREGROUND window, never every window on the desktop (Microsoft's
    # documented desktop-subtree stack-overflow hazard). An explicit scope
    # that matched nothing yields an EMPTY set (the caller answers no
    # match; never the desktop root as a fake scope).
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $scopes = @()
    $procNeedle = $null
    if ($null -ne $selector['process_name'] -and ([string]$selector['process_name']) -ne '') {
        $procNeedle = ([string]$selector['process_name']).Trim().ToLowerInvariant() -replace '\.exe$', ''
    }
    if ($null -ne $selector['hwnd']) {
        try {
            $byHandle = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr][long]$selector['hwnd'])
            if ($null -ne $byHandle) {
                if ($null -ne $procNeedle) {
                    $pn = Get-ElementProcessName $byHandle
                    if ($null -eq $pn -or $pn -ne $procNeedle) { return @() }
                }
                return @($byHandle)
            }
        } catch { }
        return @()
    }
    if ($selector['window_title']) {
        $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, [string]$selector['window_title'])
        $found = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cond)
        if ($null -ne $found -and $found.Count -gt 0) {
            if ($null -ne $procNeedle) {
                $pn = Get-ElementProcessName $found[0]
                if ($null -eq $pn -or $pn -ne $procNeedle) { return @() }
            }
            return @($found[0])
        }
        return @()
    }
    $needle = $null
    if ($null -ne $selector['window_title_contains'] -and ([string]$selector['window_title_contains']) -ne '') {
        $needle = ([string]$selector['window_title_contains']).ToLowerInvariant()
    }
    if ($null -ne $needle -or $null -ne $procNeedle) {
        # window_title_contains / process_name select the TARGET WINDOWS:
        # top-level children of the desktop filtered by title substring
        # (case-insensitive) and/or owning process name. The element
        # search then runs INSIDE each selected window.
        $windows = $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($w in $windows) {
            $ok = $true
            if ($null -ne $needle) {
                $nm = $null
                try { $nm = ([string]$w.Current.Name).ToLowerInvariant() } catch { $nm = $null }
                if ($null -eq $nm -or $nm.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { $ok = $false }
            }
            if ($ok -and $null -ne $procNeedle) {
                $pn = Get-ElementProcessName $w
                if ($null -eq $pn -or $pn -ne $procNeedle) { $ok = $false }
            }
            if ($ok) { $scopes += $w }
        }
        return $scopes
    }
    $explicitWindow = ($null -ne $selector['hwnd'] -or $null -ne $selector['window_title'] -or $null -ne $selector['window_title_contains'])
    $scopeName = 'foreground'
    if ($null -ne $selector['scope'] -and ([string]$selector['scope']) -ne '') { $scopeName = [string]$selector['scope'] }
    if ($scopeName -eq 'all_windows') {
        # The breadth escape hatch: search inside EVERY top-level window.
        $all = $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($w in $all) { $scopes += $w }
        return $scopes
    }
    if ($scopeName -eq 'window' -and -not $explicitWindow) {
        # 'window' without a window selector still means the foreground
        # window (there is nothing else it could name).
        $scopeName = 'foreground'
    }
    # foreground (the default): the current foreground window only.
    try {
        $h = [HypervMcp.Uia.Native]::GetForegroundWindow()
        if ($h -ne [IntPtr]::Zero) {
            $fw = [System.Windows.Automation.AutomationElement]::FromHandle($h)
            if ($null -ne $fw) { return @($fw) }
        }
    } catch { }
    return @()
}

function New-WalkCache {
    # Issue #136 batched reads: ONE CacheRequest carrying the element
    # properties, the state properties and the pattern-availability
    # properties. ValuePattern.Value is DELIBERATELY EXCLUDED: caching IS
    # prefetching, so the walk must never fetch a password field's value -
    # the value leg runs only for elements the cache already proved are
    # NOT password fields (see Get-ElementResult).
    $cache = New-Object System.Windows.Automation.CacheRequest
    $cache.TreeScope = [System.Windows.Automation.TreeScope]::Element
    $cache.TreeFilter = [System.Windows.Automation.Condition]::TrueCondition
    $cache.AutomationElementMode = [System.Windows.Automation.AutomationElementMode]::Full
    foreach ($prop in @(
        [System.Windows.Automation.AutomationElement]::NameProperty,
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        [System.Windows.Automation.AutomationElement]::ClassNameProperty,
        [System.Windows.Automation.AutomationElement]::IsEnabledProperty,
        [System.Windows.Automation.AutomationElement]::IsKeyboardFocusableProperty,
        [System.Windows.Automation.AutomationElement]::IsOffscreenProperty,
        [System.Windows.Automation.AutomationElement]::BoundingRectangleProperty,
        [System.Windows.Automation.AutomationElement]::IsPasswordProperty,
        [System.Windows.Automation.AutomationElement]::HasKeyboardFocusProperty,
        [System.Windows.Automation.AutomationElement]::IsValuePatternAvailableProperty,
        [System.Windows.Automation.AutomationElement]::IsTogglePatternAvailableProperty,
        [System.Windows.Automation.AutomationElement]::IsSelectionItemPatternAvailableProperty,
        [System.Windows.Automation.AutomationElement]::IsExpandCollapsePatternAvailableProperty,
        [System.Windows.Automation.AutomationElement]::IsRangeValuePatternAvailableProperty,
        [System.Windows.Automation.AutomationElement]::IsScrollItemPatternAvailableProperty,
        [System.Windows.Automation.AutomationElement]::IsInvokePatternAvailableProperty,
        [System.Windows.Automation.TogglePattern]::ToggleStateProperty,
        [System.Windows.Automation.SelectionItemPattern]::IsSelectedProperty,
        [System.Windows.Automation.ExpandCollapsePattern]::ExpandCollapseStateProperty,
        [System.Windows.Automation.RangeValuePattern]::ValueProperty
    )) {
        # PS 5.1's UIAutomationClient CacheRequest exposes ONE "Add"
        # overload set (property or pattern) - no AddProperty/AddPattern.
        $cache.Add($prop)
    }
    foreach ($pat in @(
        [System.Windows.Automation.TogglePattern]::Pattern,
        [System.Windows.Automation.SelectionItemPattern]::Pattern,
        [System.Windows.Automation.ExpandCollapsePattern]::Pattern,
        [System.Windows.Automation.RangeValuePattern]::Pattern,
        [System.Windows.Automation.ScrollItemPattern]::Pattern
    )) {
        $cache.Add($pat)
    }
    return $cache
}

function Resolve-Target([hashtable]$selector, $cache) {
    # Returns the matched elements (an array, possibly empty), read through
    # the ACTIVE walk cache (retrieval inside the Activate() scope caches).
    # A selector with no window scope searches the FOREGROUND window; the
    # search never touches the desktop root's descendants. name_contains
    # is a literal case-insensitive substring applied TOGETHER with the
    # other conditions; process_name selected the WINDOWS upstream (in
    # Get-WindowScopeSet), so no post-filter remains.
    $list = @()
    if ($null -eq $selector) { return $list }
    $scopeSet = Get-WindowScopeSet $selector
    if ($scopeSet.Count -eq 0) { return $list }
    $condResult = ConvertTo-Condition $selector
    if ($null -ne $condResult -and -not $condResult.resolvable) { return $list }
    $conditions = @()
    if ($null -ne $condResult) { $conditions = @($condResult.conditions) }
    $nameNeedle = $null
    if ($null -ne $selector['name_contains'] -and ([string]$selector['name_contains']) -ne '') { $nameNeedle = [string]$selector['name_contains'] }
    if ($conditions.Count -eq 0 -and $null -eq $nameNeedle) {
        # No match condition at all: the first scope element is itself the
        # match (the explicit-window shape).
        return @($scopeSet[0])
    }
    $cond = [System.Windows.Automation.Condition]::TrueCondition
    if ($conditions.Count -eq 1) {
        # AndCondition requires at least two conditions.
        $cond = $conditions[0]
    } elseif ($conditions.Count -gt 1) {
        $cond = New-Object System.Windows.Automation.AndCondition($conditions)
    }
    foreach ($scope in $scopeSet) {
        $found = $null
        $pushed = $cache.Activate()
        try {
            $found = $scope.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
        } finally {
            if ($null -ne $pushed) { $pushed.Dispose() }
        }
        if ($null -eq $found) { continue }
        foreach ($el in $found) {
            if ($list.Count -ge $MaxMatches) { break }
            if ($null -ne $nameNeedle) {
                $nm = $null
                try { $nm = [string]$el.Cached.Name } catch { $nm = $null; try { $nm = [string]$el.Current.Name } catch { $nm = $null } }
                if ($null -eq $nm) { continue }
                if ($nm.IndexOf($nameNeedle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            }
            $list += $el
        }
        if ($list.Count -ge $MaxMatches) { break }
    }
    return $list
}

# Issue #129: Chromium builds its accessibility tree one Text node per glyph,
# so a label arrives as many nodes and a name selector matches nothing.
# Merge-GlyphRuns joins each maximal run of ADJACENT glyph nodes whose
# bounding rectangles share a line (within $GlyphLineTolerancePx) into ONE
# virtual element: the joined name, the run's FIRST RuntimeId (so the merged
# node stays actionable for a later invoke/act) and a rect spanning the run.
# A multi-character name, a non-Text control type, or a glyph on a different
# line terminates the run and passes through verbatim.
$GlyphLineTolerancePx = 2

function Get-ElementName($el) {
    try { return [string]$el.Current.Name } catch { return $null }
}

function Get-ElementLineY($el) {
    try { return [int]$el.Current.BoundingRectangle.Y } catch { return $null }
}

function Test-IsGlyphNode($el) {
    $nm = Get-ElementName $el
    if ($null -eq $nm -or $nm.Length -ne 1) { return $false }
    try { return (([string]$el.Current.ControlType.ProgrammaticName) -eq 'ControlType.Text') } catch { return $false }
}

function New-MergedGlyphElement($run) {
    $first = $run[0]
    if ($run.Count -eq 1) { return $first }
    $name = ($run | ForEach-Object { Get-ElementName $_ }) -join ''
    $minX = $null; $right = 0; $lineY = 0; $tallest = 0
    foreach ($e in $run) {
        try {
            $r = $e.Current.BoundingRectangle
            if ($null -eq $minX -or [int]$r.X -lt $minX) { $minX = [int]$r.X }
            if ([int]($r.X + $r.Width) -gt $right) { $right = [int]($r.X + $r.Width) }
            $lineY = [int]$r.Y
            if ([int]$r.Height -gt $tallest) { $tallest = [int]$r.Height }
        } catch { }
    }
    if ($null -eq $minX) { $minX = 0 }
    $rect = New-Object PSObject
    $rect | Add-Member -MemberType NoteProperty -Name X -Value $minX
    $rect | Add-Member -MemberType NoteProperty -Name Y -Value $lineY
    $rect | Add-Member -MemberType NoteProperty -Name Width -Value ($right - $minX)
    $rect | Add-Member -MemberType NoteProperty -Name Height -Value $tallest
    $ct = New-Object PSObject
    $ct | Add-Member -MemberType NoteProperty -Name ProgrammaticName -Value 'ControlType.Text'
    $cur = New-Object PSObject
    $cur | Add-Member -MemberType NoteProperty -Name Name -Value $name
    $cur | Add-Member -MemberType NoteProperty -Name ControlType -Value $ct
    $cur | Add-Member -MemberType NoteProperty -Name BoundingRectangle -Value $rect
    # A merged node is read through the SAME batched-read path as a real
    # element, so the cached view answers the property queries
    # Get-ElementResult makes (a plain NoteProperty set would throw
    # MethodNotFound on GetCachedPropertyValue).
    $cur | Add-Member -MemberType ScriptMethod -Name GetCachedPropertyValue -Value {
        param($p)
        if ($p -eq [System.Windows.Automation.AutomationElement]::NameProperty) { return $this.Name }
        if ($p -eq [System.Windows.Automation.AutomationElement]::ControlTypeProperty) { return $this.ControlType }
        if ($p -eq [System.Windows.Automation.AutomationElement]::BoundingRectangleProperty) { return $this.BoundingRectangle }
        if ($p -eq [System.Windows.Automation.AutomationElement]::IsEnabledProperty) { return $true }
        return $null
    }
    $cur | Add-Member -MemberType ScriptMethod -Name GetPropertyValue -Value {
        param($p)
        if ($p -eq [System.Windows.Automation.AutomationElement]::NameProperty) { return $this.Name }
        if ($p -eq [System.Windows.Automation.AutomationElement]::ControlTypeProperty) { return $this.ControlType }
        if ($p -eq [System.Windows.Automation.AutomationElement]::BoundingRectangleProperty) { return $this.BoundingRectangle }
        if ($p -eq [System.Windows.Automation.AutomationElement]::IsEnabledProperty) { return $true }
        return $null
    }
    $merged = New-Object PSObject
    $merged | Add-Member -MemberType NoteProperty -Name Current -Value $cur
    $merged | Add-Member -MemberType NoteProperty -Name Cached -Value $cur
    # The run's FIRST RuntimeId, captured eagerly: the merged node must stay
    # actionable (a later invoke/act resolves the element by this id).
    $firstRid = @()
    try { $firstRid = @($first.GetRuntimeId()) } catch { }
    $merged | Add-Member -MemberType NoteProperty -Name firstRid -Value $firstRid
    $merged | Add-Member -MemberType ScriptMethod -Name GetRuntimeId -Value { @($this.firstRid) }
    $merged | Add-Member -MemberType ScriptMethod -Name GetUpdatedCache -Value { $this }
    # A real UIA element answers GetCachedPropertyValue on ITSELF (the cache
    # is filled by GetUpdatedCache), and Get-ElementResult reads both
    # $c.Cached.* and $c.GetCachedPropertyValue on the refreshed object.
    $merged | Add-Member -MemberType ScriptMethod -Name GetCachedPropertyValue -Value {
        param($p)
        $c = $this.Cached
        if ($p -eq [System.Windows.Automation.AutomationElement]::NameProperty) { return $c.Name }
        if ($p -eq [System.Windows.Automation.AutomationElement]::ControlTypeProperty) { return $c.ControlType }
        if ($p -eq [System.Windows.Automation.AutomationElement]::BoundingRectangleProperty) { return $c.BoundingRectangle }
        if ($p -eq [System.Windows.Automation.AutomationElement]::IsEnabledProperty) { return $true }
        return $null
    }
    $merged | Add-Member -MemberType ScriptMethod -Name GetPropertyValue -Value {
        param($p)
        $c = $this.Current
        if ($p -eq [System.Windows.Automation.AutomationElement]::NameProperty) { return $c.Name }
        if ($p -eq [System.Windows.Automation.AutomationElement]::ControlTypeProperty) { return $c.ControlType }
        if ($p -eq [System.Windows.Automation.AutomationElement]::BoundingRectangleProperty) { return $c.BoundingRectangle }
        if ($p -eq [System.Windows.Automation.AutomationElement]::IsEnabledProperty) { return $true }
        return $null
    }
    return $merged
}

function Merge-GlyphRuns($elements) {
    if ($null -eq $elements -or $elements.Count -eq 0) { return @() }
    $out = @()
    $run = @()
    $runY = $null
    foreach ($el in $elements) {
        if (Test-IsGlyphNode $el) {
            $y = Get-ElementLineY $el
            if ($null -ne $y -and $run.Count -gt 0 -and $null -ne $runY -and [Math]::Abs($y - $runY) -le $GlyphLineTolerancePx) {
                $run += $el
                continue
            }
            if ($run.Count -gt 0) { $out += (New-MergedGlyphElement $run); $run = @() }
            $run = @($el)
            $runY = $y
            continue
        }
        if ($run.Count -gt 0) { $out += (New-MergedGlyphElement $run); $run = @(); $runY = $null }
        $out += $el
    }
    if ($run.Count -gt 0) { $out += (New-MergedGlyphElement $run) }
    return $out
}

function Select-One($elements, [hashtable]$selector) {
    if ($null -eq $selector) { $selector = @{} }
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

function Get-ElementResult($el, $cache) {
    # Issue #136: ONE batched read. The element is refreshed through
    # GetUpdatedCache($cache) - a single cross-process round trip that
    # fills EVERY property in the walk cache at once (the old shape made
    # ~15 separate Current.* calls per element). GetRuntimeId is never
    # cached (the one deliberate non-cached read).
    $runtimeId = @()
    try { $runtimeId = @($el.GetRuntimeId()) } catch { }
    $c = $el
    if ($null -ne $cache) {
        try { $c = $el.GetUpdatedCache($cache) } catch { $c = $el }
    }
    $rect = ''
    try {
        $r = $c.Cached.BoundingRectangle
        if ($r.IsEmpty) { $r = $c.Current.BoundingRectangle }
        $rect = '{0},{1},{2},{3}' -f [int]$r.X, [int]$r.Y, [int]$r.Width, [int]$r.Height
    } catch { }
    $name = ''
    $controlType = ''
    $automationId = ''
    $className = ''
    $enabled = $false
    $focusable = $false
    $offscreen = $false
    try { $name = [string]$c.Cached.Name } catch { try { $name = [string]$c.Current.Name } catch { } }
    try { $controlType = [string]$c.Cached.ControlType.ProgrammaticName -replace '^ControlType\.', '' } catch { try { $controlType = [string]$c.Current.ControlType.ProgrammaticName -replace '^ControlType\.', '' } catch { } }
    try { $automationId = [string]$c.Cached.AutomationId } catch { try { $automationId = [string]$c.Current.AutomationId } catch { } }
    try { $className = [string]$c.Cached.ClassName } catch { try { $className = [string]$c.Current.ClassName } catch { } }
    try { $enabled = [bool]$c.Cached.IsEnabled } catch { try { $enabled = [bool]$c.Current.IsEnabled } catch { } }
    try { $focusable = [bool]$c.Cached.IsKeyboardFocusable } catch { try { $focusable = [bool]$c.Current.IsKeyboardFocusable } catch { } }
    try { $offscreen = [bool]$c.Cached.IsOffscreen } catch { try { $offscreen = [bool]$c.Current.IsOffscreen } catch { } }
    $patterns = @()
    foreach ($pair in @(@('Invoke', [System.Windows.Automation.AutomationElement]::IsInvokePatternAvailableProperty),
                       @('Value', [System.Windows.Automation.AutomationElement]::IsValuePatternAvailableProperty),
                       @('Toggle', [System.Windows.Automation.AutomationElement]::IsTogglePatternAvailableProperty),
                       @('SelectionItem', [System.Windows.Automation.AutomationElement]::IsSelectionItemPatternAvailableProperty),
                       @('ExpandCollapse', [System.Windows.Automation.AutomationElement]::IsExpandCollapsePatternAvailableProperty),
                       @('RangeValue', [System.Windows.Automation.AutomationElement]::IsRangeValuePatternAvailableProperty),
                       @('LegacyIAccessible', 'msaa'))) {
        $avail = $false
        if ($pair[1] -eq 'msaa') {
            # The msaa bridge: advertised only when the LegacyIAccessible
            # pattern type resolved at startup (Get-HelperCapabilities).
            $avail = ($null -ne $legacyPattern)
        } else {
            try { $avail = [bool]$c.GetCachedPropertyValue($pair[1]) } catch { try { $avail = [bool]$c.Current.GetPropertyValue($pair[1]) } catch { $avail = $false } }
        }
        if ($avail) { $patterns += $pair[0] }
    }

    # --- the state block (issue #136 design 1) ---
    $state = @{}
    $isPassword = $false
    try { $isPassword = [bool]$c.Cached.IsPassword } catch { try { $isPassword = [bool]$c.Current.IsPassword } catch { } }
    $state['is_password'] = $isPassword
    try { $state['has_keyboard_focus'] = [bool]$c.Cached.HasKeyboardFocus } catch { }
    # A password field's value is NEVER fetched: IsPassword arrives with
    # the batched read BEFORE any value leg, and the value read below runs
    # only for confirmed non-password elements.
    if (-not $isPassword) {
        if ([bool]$c.GetCachedPropertyValue([System.Windows.Automation.AutomationElement]::IsValuePatternAvailableProperty)) {
            $raw = $null
            try { $raw = $c.GetCurrentPropertyValue([System.Windows.Automation.ValuePattern]::ValueProperty) } catch { $raw = $null }
            if ($null -ne $raw) {
                $text = [string]$raw
                $state['value'] = $text.Substring(0, [Math]::Min(512, $text.Length))
                $state['value_truncated'] = ($text.Length -gt 512)
            }
        }
    }
    try {
        if ([bool]$c.GetCachedPropertyValue([System.Windows.Automation.AutomationElement]::IsTogglePatternAvailableProperty)) {
            $ts = $null
            try { $ts = $c.GetCachedPattern([System.Windows.Automation.TogglePattern]::Pattern).Cached.ToggleState } catch { $ts = $null }
            if ($null -ne $ts) { $state['toggle_state'] = ([string]$ts).Split('+')[-1].ToLowerInvariant() }
        }
    } catch { }
    try {
        if ([bool]$c.GetCachedPropertyValue([System.Windows.Automation.AutomationElement]::IsSelectionItemPatternAvailableProperty)) {
            $sel = $null
            try { $sel = $c.GetCachedPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Cached.IsSelected } catch { $sel = $null }
            if ($null -ne $sel) { $state['selected'] = [bool]$sel }
        }
    } catch { }
    try {
        if ([bool]$c.GetCachedPropertyValue([System.Windows.Automation.AutomationElement]::IsExpandCollapsePatternAvailableProperty)) {
            $ecs = $null
            try { $ecs = $c.GetCachedPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Cached.ExpandCollapseState } catch { $ecs = $null }
            if ($null -ne $ecs) { $state['expand_state'] = ([string]$ecs).Split('+')[-1].ToLowerInvariant() }
        }
    } catch { }
    try {
        if ([bool]$c.GetCachedPropertyValue([System.Windows.Automation.AutomationElement]::IsRangeValuePatternAvailableProperty)) {
            $rv = $null
            try { $rv = $c.GetCachedPattern([System.Windows.Automation.RangeValuePattern]::Pattern).Cached.Value } catch { $rv = $null }
            if ($null -ne $rv) { $state['range_value'] = [double]$rv }
        }
    } catch { }

    @{
        element_id = ($runtimeId -join ':')
        name = $name
        control_type = $controlType
        automation_id = $automationId
        class_name = $className
        enabled = $enabled
        keyboard_focusable = $focusable
        offscreen = $offscreen
        patterns = $patterns
        rect = $rect
        state = $state
    }
}

function Walk-Tree($el, $d, $cap, [ref]$seen, $cache, $walker) {
    if ($seen.Value -ge $cap -or $d -lt 0) { return $null }
    $seen.Value = $seen.Value + 1
    $node = Get-ElementResult $el $cache
    $children = New-Object System.Collections.Generic.List[object]
    if ($d -gt 0) {
        # One level at a time THROUGH THE CACHE REQUEST (issue #136): the
        # TreeWalker overloads that take the request cache the children at
        # retrieval - no per-node uncached re-reads.
        $kids = @()
        $kid = $null
        try { $kid = $walker.GetFirstChild($el, $cache) } catch { $kid = $null }
        while ($null -ne $kid -and $kids.Count -lt $cap) {
            $kids += $kid
            try { $kid = $walker.GetNextSibling($kid, $cache) } catch { $kid = $null }
        }
        foreach ($k in $kids) {
            if ($seen.Value -ge $cap) { break }
            $child = Walk-Tree $k ($d - 1) $cap $seen $cache $walker
            if ($null -ne $child) { [void]$children.Add($child) }
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

# ---------------------------------------------------------------------------
# snapshot-bound element refs (issue #137)
# ---------------------------------------------------------------------------

# Per-window snapshot tables: live{snapshot_id -> {index -> element}} plus
# an ISSUED-IDS tombstone set. A ref whose snapshot id is in the
# tombstones but not in live is EVICTED -> stale_ref; a ref whose id was
# never issued -> unknown_ref; a live hit whose element fails
# GetRuntimeId -> stale_ref (round-2 F3 semantics). Two live snapshots per
# window key, FIFO eviction.
# ONE synchronized object shared with every worker/child runspace (via
# $sessionVariables): live{snapshot_id -> {index -> element}} tables plus
# an issued-ids tombstone set per window, and the snapshot counter riding
# inside the same lock (issue #137; the per-request child runspaces would
# otherwise each see their own empty copy).
$script:SnapshotTables = [hashtable]::Synchronized(@{
    counter = 0
    windows = @{}
})

function Get-ElementIdScopeSelector($selector) {
    # element_id / ref resolution scope: the selector's own window
    # scoping when it names one, else all_windows (per-window bounded
    # searches with the MaxMatches cap - never the desktop root as one
    # search root).
    if ($null -ne $selector -and ($null -ne $selector['hwnd'] -or $null -ne $selector['window_title'] -or $null -ne $selector['window_title_contains'] -or $null -ne $selector['process_name'] -or $null -ne $selector['scope'])) {
        return $selector
    }
    return @{ scope = 'all_windows' }
}

function Enter-Snapshot([hashtable]$selector, [int]$cap, $cache) {
    # Walks ONE window (the foreground window by default) and registers
    # the walk as the window's newest snapshot. Returns the answer frame
    # (snapshot_id + entries).
    $set = @(Get-WindowScopeSet $selector)
    if ($set.Count -eq 0) {
        return @{ ok = $false; error_class = 'no_foreground_window'; error = 'no window is scoped for the snapshot' }
    }
    $window = $set[0]
    $windowKey = $null
    try { $windowKey = (@($window.GetRuntimeId()) -join ':') } catch { }
    $entries = @()
    $table = @{}
    $index = 0
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    # Depth-aware bounded walk (issue #137 C10: entries carry depth so the
    # host renders them indented): one level at a time THROUGH the cache
    # request, breadth-first, capped.
    $queue = New-Object System.Collections.Generic.List[object]
    $queue.Add(@{ el = $window; depth = 0 })
    while ($queue.Count -gt 0 -and $entries.Count -lt $cap) {
        $item = $queue[0]
        $queue.RemoveAt(0)
        $el = $item['el']
        $depth = [int]$item['depth']
        $rid = ''
        try { $rid = (@($el.GetRuntimeId()) -join ':') } catch { }
        if ($rid -eq '') { continue }
        $table[$index] = $el
        $result = Get-ElementResult $el $cache
        $result['ref'] = ('s{0:x}:{1}' -f $SnapshotStore.counter, $index)
        $result['depth'] = $depth
        $entries += $result
        $index += 1
        if ($depth -ge 12) { continue }
        # The snapshot's CAPTURE bound (12): elements below 12 levels are
        # not captured at all (no entry, no ref, nothing rendered) - a
        # deliberately smaller display bound than the inspect clamp (32),
        # which remains the deep-tree reading bound (#136 AC9). Disclosed
        # in the README's hyperv_ui_snapshot description.
        $kid = $null
        try { $kid = $walker.GetFirstChild($el, $cache) } catch { $kid = $null }
        while ($null -ne $kid -and $entries.Count -lt $cap) {
            $queue.Add(@{ el = $kid; depth = $depth + 1 })
            try { $kid = $walker.GetNextSibling($kid, $cache) } catch { $kid = $null }
        }
    }
    if ($null -eq $windowKey -and $entries.Count -gt 0) {
        # A window whose RuntimeId cannot be read cannot register a
        # snapshot table - its refs would be unresolvable, so refuse
        # rather than stamp refs no later call can address.
        return @{ ok = $false; error_class = 'no_foreground_window'; error = 'the scoped window exposed no readable identity for the snapshot' }
    }
    if ($null -ne $windowKey -and $index -gt 0) {
        # The WHOLE read-modify-write holds the store lock: the counter,
        # the per-window table creation, the FIFO eviction and the insert
        # are one transaction, and Resolve-Ref's lookup takes the same
        # lock - concurrent read verbs may otherwise race the plain
        # hashtable/HashSet members.
        [System.Threading.Monitor]::Enter($SnapshotStore.SyncRoot)
        try {
            $SnapshotStore.counter += 1
            $snapshotId = '{0:x}' -f $SnapshotStore.counter
            # Stamp every entry's ref with the ASSIGNED snapshot id (the
            # walk loop stamped a pre-increment placeholder; without this
            # re-stamp every returned ref would resolve against the
            # PREVIOUS snapshot or unknown_ref).
            foreach ($e in $entries) { $e['ref'] = ('s{0}:{1}' -f $snapshotId, ($e['ref'] -split ':')[-1]) }
            $tbl = $SnapshotStore.windows[$windowKey]
            if ($null -eq $tbl) {
                $tbl = @{ live = @{}; tombstones = New-Object System.Collections.Generic.HashSet[string] }
                $SnapshotStore.windows[$windowKey] = $tbl
            }
            # FIFO eviction at two live snapshots per window: evicted ids
            # move to the tombstones (stale_ref on later use), never
            # vanish.
            while ($tbl.live.Count -ge 2) {
                $oldest = @($tbl.live.Keys | Sort-Object { [Convert]::ToInt64($_, 16) })[0]
                [void]$tbl.tombstones.Add($oldest)
                [void]$tbl.live.Remove($oldest)
            }
            $tbl.live[$snapshotId] = $table
        } finally {
            [System.Threading.Monitor]::Exit($SnapshotStore.SyncRoot)
        }
    }
    if ($entries.Count -eq 0) {
        return @{ ok = $false; error_class = 'no_foreground_window'; error = 'the scoped window exposed no elements for the snapshot' }
    }
    return @{ ok = $true; result = @{ snapshot_id = ('s' + $snapshotId); entries = $entries } }
}

function Resolve-Ref([string]$refText) {
    # Constant-time table lookup: s<hex>:<dec>. never-issued -> unknown_ref;
    # issued-but-evicted -> stale_ref with reason 'evicted'; live table
    # entry -> the element reference is copied out under the store lock,
    # then probed for liveness OUTSIDE the lock: an uncached property read
    # (GetCurrentPropertyValue with ignoreDefaultValue=$true) is the only call
    # verified by executed probes to throw ElementNotAvailableException on
    # a dead element (GetRuntimeId and Current.* keep ANSWERING stale
    # values). dead -> stale_ref with reason 'dead'; alive -> the element.
    $parts = $refText -split ':'
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^s[0-9a-fA-F]+$' -or $parts[1] -notmatch '^[0-9]+$') {
        return @{ element = $null; error_class = 'unknown_ref'; error = "the ref $refText was never issued by any hyperv_ui_snapshot" }
    }
    $sid = $parts[0].Substring(1).ToLowerInvariant()
    $idx = [int]$parts[1]
    # The lookup holds the SAME store lock Enter-Snapshot's
    # read-modify-write holds: concurrent read verbs race these plain
    # hashtable/HashSet members otherwise. The element reference is
    # copied out under this lock; the liveness probe runs AFTER the
    # lock releases (a cross-process provider call can block - never
    # hold the store lock across one).
    $resolvedEl = $null
    $lookupClass = 'unknown_ref'
    $lookupError = "the ref $refText was never issued by any hyperv_ui_snapshot"
    $lookupReason = $null
    [System.Threading.Monitor]::Enter($SnapshotStore.SyncRoot)
    try {
        foreach ($tbl in $SnapshotStore.windows.Values) {
            if ($tbl.live.ContainsKey($sid)) {
                $table = $tbl.live[$sid]
                if (-not $table.ContainsKey($idx)) {
                    $lookupClass = 'unknown_ref'
                    $lookupError = "the ref $refText was never issued by any hyperv_ui_snapshot"
                } else {
                    $resolvedEl = $table[$idx]
                    $lookupClass = $null
                }
            }
            if ($tbl.tombstones.Contains($sid)) {
                $lookupClass = 'stale_ref'
                $lookupReason = 'evicted'
                $lookupError = "the snapshot $refText was evicted (two newer snapshots taken for this window); take a fresh hyperv_ui_snapshot"
            }
        }
    } finally {
        [System.Threading.Monitor]::Exit($SnapshotStore.SyncRoot)
    }
    if ($null -ne $lookupClass) {
        return @{ element = $null; error_class = $lookupClass; reason = $lookupReason; error = $lookupError }
    }
    # The liveness probe runs OUTSIDE the store lock: an uncached property
    # read forces a provider call that throws ElementNotAvailableException
    # on a dead element (executed probe, 2026-11-13: GetRuntimeId and
    # Current.* keep answering stale values on a dead element). The catch
    # is NARROW (critic round 2): only ElementNotAvailableException means
    # dead -- a hung-but-alive provider raising TimeoutException/COM
    # failures must surface as helper_error, not lie gone.
    $elAlive = $true
    try { $null = $resolvedEl.GetCurrentPropertyValue([System.Windows.Automation.AutomationElement]::NameProperty, $true) } catch [System.Windows.Automation.ElementNotAvailableException] { $elAlive = $false }
    if (-not $elAlive) {
        return @{ element = $null; error_class = 'stale_ref'; reason = 'dead'; error = "the referenced element is gone; take a fresh hyperv_ui_snapshot" }
    }
    return @{ element = $resolvedEl; error_class = $null; reason = $null; error = $null }
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
                dpi_aware = $dpiDeclared
            }
        }
    }

    $selector = $req['selector']
    if ($null -eq $selector -and $req.ContainsKey('args') -and $null -ne $req['args'] -and $req['args'] -is [hashtable]) {
        $selector = $req['args']['selector']
    }
    if ($null -ne $selector -and $selector -isnot [hashtable]) { $selector = $null }

    if ($verb -eq 'enable_accessibility') {
        # Issue #129: Chromium builds its accessibility tree on demand. The
        # host sends this BEFORE resolving a selector on the electron path;
        # the helper asks the renderer for its tree by READING a property
        # from it (a UI Automation client turns the tree on by actually
        # reading it -- chromium/ui/accessibility/platform/ax_platform.cc
        # records that the old screen-reader signal alone is no longer
        # trusted). The answer reports whether a tree is now reachable.
        $available = $false
        try {
            $root = [System.Windows.Automation.AutomationElement]::RootElement
            if ($null -ne $root) {
                $null = $root.Current.Name
                $available = $true
            }
        } catch { $available = $false }
        if (-not $available) {
            return @{ ok = $true; result = @{ available = $false } }
        }
        # The renderer tree is reachable only when the foreground window's
        # subtree yields element nodes; an application that never turned its
        # renderer accessibility on answers available:false rather than an
        # empty match list.
        $found = 0
        try {
            $fg = Get-ForegroundWindow
            if ($null -ne $fg) {
                $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
                $node = $walker.GetFirstChild($fg)
                while ($null -ne $node -and $found -lt 1) {
                    $found++
                    $node = $walker.GetNextSibling($node)
                }
            }
        } catch { $found = 0 }
        return @{ ok = $true; result = @{ available = ($found -gt 0) } }
    }

    if ($verb -eq 'snapshot') {
        # BEFORE element resolution (the selector here is a WINDOW
        # selector, not an element address): a no-selector snapshot
        # targets the foreground window and must never run the
        # element-resolution path (which refuses selector-less requests).
        $cap = 250
        if ($null -ne $req['args'] -and $req['args'] -is [hashtable]) {
            if ($null -ne $req['args']['max_elements']) { $cap = [Math]::Min([int]$req['args']['max_elements'], $MaxElements) }
        }
        $snapCache = New-WalkCache
        return (Enter-Snapshot $selector $cap $snapCache)
    }

    if ($verb -eq 'inspect') {
        $depth = 3; $cap = 200
        if ($null -ne $req['args'] -and $req['args'] -is [hashtable]) {
            if ($null -ne $req['args']['depth']) { $depth = [Math]::Min([int]$req['args']['depth'], $MaxDepth) }
            if ($null -ne $req['args']['max_elements']) { $cap = [Math]::Min([int]$req['args']['max_elements'], $MaxElements) }
        }
        # inspect HONOURS the selector it is given: the walk is scoped to
        # the matched element; with NO selector it starts at the FOREGROUND
        # window (issue #136: never the desktop root). No match (or an
        # ambiguous one) yields an empty tree.
        $cache = New-WalkCache
        $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
        $startEl = $null
        if ($null -ne $selector) {
            $elements = @(Resolve-Target $selector $cache)
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
        } else {
            $fg = @(Get-WindowScopeSet @{})
            if ($fg.Count -gt 0) { $startEl = $fg[0] }
        }
        if ($null -eq $startEl) {
            return @{ ok = $true; result = @{ elements = 0; truncated = $false; tree = $null } }
        }
        $seen = 0
        $tree = Walk-Tree $startEl $depth $cap ([ref]$seen) $cache $walker
        return @{ ok = $true; result = @{ elements = $seen; truncated = ($seen -ge $cap); tree = $tree } }
    }

    $cache = New-WalkCache

    if ($verb -eq 'find' -or $verb -eq 'wait_for') {
        $elements = @()
        if ($verb -eq 'wait_for') {
            $argsPair = $req['args']
            $gone = $false; $budget = 30
            if ($null -ne $argsPair -and $argsPair -is [hashtable]) {
                if ($null -ne $argsPair['gone']) { $gone = [bool]$argsPair['gone'] }
                if ($null -ne $argsPair['timeout_s']) { $budget = [Math]::Min([int]$argsPair['timeout_s'], 120) }
            }
            $deadline = [DateTime]::UtcNow.AddSeconds($budget)
            # ref/element_id addresses resolve INSIDE the poll loop: a
            # null selector does not mean the element is absent (a
            # gone-wait on a live ref answered gone immediately).
            $waitRef = $null
            if ($req.ContainsKey('ref') -and $null -ne $req['ref']) { $waitRef = [string]$req['ref'] }
            $waitElementId = $null
            if ($req.ContainsKey('element_id') -and $null -ne $req['element_id']) { $waitElementId = [string]$req['element_id'] }
            while ([DateTime]::UtcNow -lt $deadline) {
                if ($null -ne $waitRef) {
                    $resolved = Resolve-Ref $waitRef
                    # A ref the helper never issued is a CALLER error, not
                    # an absent element: answer unknown_ref immediately
                    # instead of a misleading gone verdict. An EVICTED
                    # snapshot is not absence - the element may still be
                    # on screen - so a gone-wait answers stale_ref there
                    # too. Only a probe-verified DEAD element answers
                    # gone:true (the element really is gone).
                    if ($resolved.error_class -eq 'unknown_ref') {
                        return @{ ok = $false; error_class = 'unknown_ref'; error = $resolved.error }
                    }
                    if ($resolved.error_class -eq 'stale_ref') {
                        if ($gone -and $resolved.reason -eq 'dead') { return @{ ok = $true; result = @{ gone = $true } } }
                        return @{ ok = $false; error_class = 'stale_ref'; error = $resolved.error }
                    }
                    $present = ($null -eq $resolved.error_class)
                } elseif ($null -ne $waitElementId) {
                    $found = $null
                    foreach ($scope in (Get-WindowScopeSet (Get-ElementIdScopeSelector $selector))) {
                        $scan = $null
                        $pushedWait = $cache.Activate()
                        try {
                            $scan = $scope.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
                        } finally {
                            if ($null -ne $pushedWait) { $pushedWait.Dispose() }
                        }
                        foreach ($candidate in $scan) {
                            $rid = ''
                            try { $rid = (@($candidate.GetRuntimeId()) -join ':') } catch { }
                            if ($rid -eq $waitElementId) { $found = $candidate; break }
                        }
                        if ($null -ne $found) { break }
                    }
                    $elements = @($found)
                    $present = ($null -ne $found)
                } else {
                    $elements = @(Resolve-Target $selector $cache)
                    $present = ($null -ne $elements -and $elements.Count -gt 0)
                }
                if ($gone -and -not $present) { return @{ ok = $true; result = @{ gone = $true } } }
                if (-not $gone -and $present) { break }
                Start-Sleep -Milliseconds 400
            }
        }
        if ($null -ne $selector) {
            if ($req['adapter'] -eq 'electron') {
                # Issue #129: Chromium's per-glyph nodes must be merged
                # BEFORE the selector's name is matched -- a name condition
                # applied to unmerged glyphs matches nothing. Collect the
                # scope WITHOUT the name condition, merge the runs, then
                # match the name/name_contains predicates against the JOINED
                # names.
                $collector = @{}
                foreach ($k in @($selector.Keys)) {
                    if ($k -ne 'name' -and $k -ne 'name_contains') { $collector[$k] = $selector[$k] }
                }
                $elements = @(Merge-GlyphRuns (Resolve-Target $collector $cache))
                $wantName = $null
                if ($selector.ContainsKey('name') -and $null -ne $selector['name']) { $wantName = [string]$selector['name'] }
                $needle = $null
                if ($selector.ContainsKey('name_contains') -and $null -ne $selector['name_contains']) { $needle = [string]$selector['name_contains'] }
                $matched = @()
                foreach ($el in $elements) {
                    $nm = Get-ElementName $el
                    if ($null -eq $nm) { continue }
                    if ($null -ne $wantName -and $nm -ne $wantName) { continue }
                    if ($null -ne $needle -and $nm.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
                    $matched += $el
                }
                $elements = $matched
            } else {
                $elements = @(Resolve-Target $selector $cache)
            }
        }
        if ($req.ContainsKey('ref') -and $null -ne $req['ref']) {
            # issue #137: snapshot-bound ref, resolved through the
            # per-window snapshot table (stale_ref = issued-but-evicted or
            # a dead element; unknown_ref = never issued).
            $resolved = Resolve-Ref ([string]$req['ref'])
            if ($null -ne $resolved.error_class) {
                return @{ ok = $false; error_class = $resolved.error_class; error = $resolved.error }
            }
            $elements = @($resolved.element)
        }
        if ($req.ContainsKey('element_id') -and $null -ne $req['element_id']) {
            # element_id IS a UIA RuntimeId: resolve the live element by it
            # INSIDE the scoped windows (issue #136: never a desktop-root
            # scan). An unresolvable id answers like a selector no-match
            # (an empty element list), which is the find verb's contract;
            # the mutating verbs refuse an unknown id with
            # element_not_found.
            $idWanted = [string]$req['element_id']
            $elements = @()
            foreach ($scope in (Get-WindowScopeSet (Get-ElementIdScopeSelector $selector))) {
                $pushed = $cache.Activate()
                try {
                    $scan = $scope.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
                } finally {
                    if ($null -ne $pushed) { $pushed.Dispose() }
                }
                foreach ($candidate in $scan) {
                    $rid = ''
                    try { $rid = (@($candidate.GetRuntimeId()) -join ':') } catch { }
                    if ($rid -eq $idWanted) { $elements = @($candidate); break }
                }
                if ($elements.Count -gt 0) { break }
            }
        }
        if ($null -eq $elements -or $elements.Count -eq 0) {
            return @{ ok = $true; result = @{ elements = @() } }
        }
        $one = Select-One $elements $selector
        if ($null -ne $one -and $one.ambiguous) {
            return @{ ok = $false; error_class = 'ambiguous_selector'; error = 'the selector matched more than one element'; candidates = $one.candidates }
        }
        return @{ ok = $true; result = @{ elements = @(Get-ElementResult $one $cache) } }
    }

    $elementIdWanted = $null
    if ($req.ContainsKey('element_id')) { $elementIdWanted = [string]$req['element_id'] }
    elseif ($null -ne $req['args'] -and $req['args'] -is [hashtable] -and $null -ne $req['args']['element_id']) { $elementIdWanted = [string]$req['args']['element_id'] }
    $refWanted = $null
    if ($req.ContainsKey('ref') -and $null -ne $req['ref']) { $refWanted = [string]$req['ref'] }
    elseif ($null -ne $req['args'] -and $req['args'] -is [hashtable] -and $null -ne $req['args']['ref']) { $refWanted = [string]$req['args']['ref'] }

    $el = $null
    if ($refWanted) {
        $resolved = Resolve-Ref $refWanted
        if ($null -ne $resolved.error_class) {
            return @{ ok = $false; error_class = $resolved.error_class; error = $resolved.error }
        }
        $el = $resolved.element
    } elseif ($elementIdWanted) {
        # element_id IS a UIA RuntimeId: resolve the live element by it
        # INSIDE the scoped windows (issue #136: never a desktop-root
        # scan).
        foreach ($scope in (Get-WindowScopeSet (Get-ElementIdScopeSelector $selector))) {
            $pushed = $cache.Activate()
            try {
                $scan = $scope.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
            } finally {
                if ($null -ne $pushed) { $pushed.Dispose() }
            }
            foreach ($candidate in $scan) {
                $rid = ''
                try { $rid = (@($candidate.GetRuntimeId()) -join ':') } catch { }
                if ($rid -eq $elementIdWanted) { $el = $candidate; break }
            }
            if ($null -ne $el) { break }
        }
        if ($null -eq $el) {
            return @{ ok = $false; error_class = 'element_not_found'; error = "no live element matches element_id $elementIdWanted" }
        }
    } else {
        $elements = @(Resolve-Target $selector $cache)
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
    if ($verb -eq 'focus' -or $verb -eq 'invoke' -or $verb -eq 'set_value' -or $verb -eq 'act') {
        if ($locked -or -not (Test-OwnsInputDesktop)) {
            return @{ ok = $false; error_class = 'no_interactive_desktop'; error = 'the session is locked; this verb needs the interactive desktop' }
        }
    }

    if ($verb -eq 'act') {
        # Issue #137: one explicit action. The action set is closed here
        # as well as on the host (both ends refuse before any dispatch).
        $argsPair = $req['args']
        $actionName = ''
        $actionValue = $null
        if ($null -ne $argsPair -and $argsPair -is [hashtable]) {
            if ($null -ne $argsPair['action']) { $actionName = [string]$argsPair['action'] }
            if ($argsPair.ContainsKey('value')) { $actionValue = $argsPair['value'] }
        }
        $actionSet = @('collapse', 'click', 'expand', 'focus', 'invoke',
                       'scroll_into_view', 'select', 'set_value', 'toggle_off', 'toggle_on')
        if ($actionSet -notcontains $actionName) {
            return @{ ok = $false; error_class = 'invalid_request'; error = "unknown action $actionName" }
        }
        if ($actionName -eq 'set_value' -and $null -eq $actionValue) {
            return @{ ok = $false; error_class = 'invalid_request'; error = 'act set_value requires a value' }
        }
        if ($actionName -ne 'set_value' -and $null -ne $actionValue) {
            return @{ ok = $false; error_class = 'invalid_request'; error = 'value= applies only to the set_value action' }
        }
        # Post-action state refresh: GetUpdatedCache re-reads the element
        # through the walk cache in ONE round trip (issue #136).
        $refreshed = $el
        try { $refreshed = $el.GetUpdatedCache($cache) } catch { $refreshed = $el }

        if ($actionName -eq 'click') {
            # Scroll into view FIRST, then check enabled + onscreen + a
            # clickable point; ANY failed check answers not_actionable and
            # NO input is sent (the host dispatches the click it receives
            # a point for).
            try {
                if ([bool]$refreshed.GetUpdatedCache($cache).GetCachedPropertyValue([System.Windows.Automation.AutomationElement]::IsScrollItemPatternAvailableProperty)) {
                    $si = $refreshed.GetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern)
                    if ($null -ne $si) {
                        $si.ScrollIntoView()
                        # Re-read AFTER the scroll: the offscreen/point
                        # checks below must see the scrolled-into-view
                        # state, not the pre-scroll cache.
                        try { $refreshed = $refreshed.GetUpdatedCache($cache) } catch { }
                    }
                }
            } catch { }
            $clickable = $false
            $pt = $null
            try {
                if (-not [bool]$refreshed.Cached.IsEnabled) { throw 'disabled' }
                if ([bool]$refreshed.Cached.IsOffscreen) { throw 'offscreen' }
                $pt = $refreshed.GetClickablePoint()
                $clickable = $true
            } catch { $clickable = $false }
            if (-not $clickable -or $null -eq $pt) {
                return @{ ok = $false; error_class = 'not_actionable'; error = 'the element is disabled, off screen, or exposes no clickable point' }
            }
            return @{ ok = $true; result = @{ point = @([int]$pt.X, [int]$pt.Y) } }
        }

        if ($actionName -eq 'scroll_into_view') {
            try {
                $si = $refreshed.GetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern)
                if ($null -eq $si) { return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes no ScrollItemPattern' } }
                $si.ScrollIntoView()
            } catch {
                return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes no ScrollItemPattern' }
            }
            return @{ ok = $true; result = @{ action = 'scroll_into_view'; state = (Get-ElementResult $refreshed $cache) } }
        }

        if ($actionName -eq 'toggle_on' -or $actionName -eq 'toggle_off') {
            # No-op when already in the target state (issue #137 design 3).
            $want = 'On'
            if ($actionName -eq 'toggle_off') { $want = 'Off' }
            try {
                $pat = $refreshed.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
            } catch {
                return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes no TogglePattern' }
            }
            $current = ([string]$pat.Cached.ToggleState).Split('+')[-1]
            if ($current -ieq $want) {
                return @{ ok = $true; result = @{ action = $actionName; pattern = 'Toggle'; noop = $true; state = (Get-ElementResult $refreshed $cache) } }
            }
            try { $pat.Toggle() } catch {
                return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element refused the toggle' }
            }
            $after = $null
            try { $after = $el.GetUpdatedCache($cache) } catch { $after = $el }
            return @{ ok = $true; result = @{ action = $actionName; pattern = 'Toggle'; state = (Get-ElementResult $after $cache) } }
        }

        if ($actionName -eq 'set_value') {
            $text = [string]$actionValue
            if ($text.Length -gt $MaxValueChars) {
                return @{ ok = $false; error_class = 'invalid_request'; error = 'the value exceeds the 64 KiB bound' }
            }
            $fired = $null
            if ($null -ne (Invoke-Pattern $refreshed ([System.Windows.Automation.ValuePattern]::Pattern) 'setvalue' $text)) {
                $fired = 'Value'
            } elseif ($null -ne $legacyPattern) {
                $legacy = $null
                try { $legacy = $refreshed.GetCurrentPattern($legacyPattern) } catch { $legacy = $null }
                if ($null -ne $legacy) {
                    try { $legacy.SetValue($text); $fired = 'LegacyIAccessible' } catch { $fired = $null }
                }
            }
            if ($null -eq $fired) {
                return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes no ValuePattern or the msaa LegacyIAccessible bridge' }
            }
            $after = $null
            try { $after = $el.GetUpdatedCache($cache) } catch { $after = $el }
            return @{ ok = $true; result = @{ action = 'set_value'; pattern = $fired; length_set = $text.Length; state = (Get-ElementResult $after $cache) } }
        }

        if ($actionName -eq 'focus') {
            try { $refreshed.SetFocus() } catch { }
            $focused = $false
            try { $focused = [bool]$refreshed.Cached.HasKeyboardFocus } catch { try { $focused = [bool]$refreshed.Current.HasKeyboardFocus } catch { } }
            return @{ ok = $true; result = @{ action = 'focus'; focused = $focused; state = (Get-ElementResult $refreshed $cache) } }
        }

        if ($actionName -eq 'select' -or $actionName -eq 'expand' -or $actionName -eq 'collapse') {
            $patternMap = @{
                'select' = [System.Windows.Automation.SelectionItemPattern]::Pattern
                'expand' = [System.Windows.Automation.ExpandCollapsePattern]::Pattern
                'collapse' = [System.Windows.Automation.ExpandCollapsePattern]::Pattern
            }
            $verbMap = @{ 'select' = 'select'; 'expand' = 'expand'; 'collapse' = 'collapse' }
            $patternType = $patternMap[$actionName]
            $fired = Invoke-Pattern $refreshed $patternType $verbMap[$actionName] $null
            if ($null -eq $fired) {
                return @{ ok = $false; error_class = 'unsupported_capability'; error = "the element exposes no pattern for $actionName" }
            }
            $after = $null
            try { $after = $el.GetUpdatedCache($cache) } catch { $after = $el }
            return @{ ok = $true; result = @{ action = $actionName; pattern = ($patternType.ProgrammaticName -replace 'Identifiers\\.Pattern$', '' -replace 'Pattern$', ''); state = (Get-ElementResult $after $cache) } }
        }

        if ($actionName -eq 'invoke') {
            # Invoke with the invoke/toggle/select/expand fallback the
            # legacy verb chain used, reporting WHICH pattern fired.
            $fired = $null
            if ($null -ne (Invoke-Pattern $refreshed ([System.Windows.Automation.InvokePattern]::Pattern) 'invoke' $null)) { $fired = 'Invoke' }
            if ($null -eq $fired -and $null -ne (Invoke-Pattern $refreshed ([System.Windows.Automation.TogglePattern]::Pattern) 'toggle' $null)) { $fired = 'Toggle' }
            if ($null -eq $fired -and $null -ne (Invoke-Pattern $refreshed ([System.Windows.Automation.SelectionItemPattern]::Pattern) 'select' $null)) { $fired = 'SelectionItem' }
            if ($null -eq $fired -and $null -ne (Invoke-Pattern $refreshed ([System.Windows.Automation.ExpandCollapsePattern]::Pattern) 'expand' $null)) { $fired = 'ExpandCollapse' }
            if ($null -eq $fired -and $null -ne $legacyPattern) {
                $legacy = $null
                try { $legacy = $refreshed.GetCurrentPattern($legacyPattern) } catch { $legacy = $null }
                if ($null -ne $legacy) {
                    try { $legacy.DoDefaultAction(); $fired = 'LegacyIAccessible' } catch { $fired = $null }
                }
            }
            if ($null -eq $fired) {
                return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes none of the tried patterns: Invoke, Toggle, SelectionItem, ExpandCollapse, LegacyIAccessible (msaa bridge)' }
            }
            $after = $null
            try { $after = $el.GetUpdatedCache($cache) } catch { $after = $el }
            return @{ ok = $true; result = @{ action = 'invoke'; pattern = $fired; state = (Get-ElementResult $after $cache) } }
        }

        return @{ ok = $false; error_class = 'invalid_request'; error = "unknown action $actionName" }
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
# (the capabilities list is computed by Get-HelperCapabilities above)
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

# Issue #136: advertise msaa ONLY when the bridge pattern type resolved -
# never a hardcoded capability list the client cannot trust.
function Get-HelperCapabilities {
    $caps = @('uia')
    if ($null -ne $legacyPattern) { $caps += 'msaa' }
    # Issue #129: the helper implements the electron adapter's behaviour (the
    # renderer-accessibility enable and the per-glyph run merge), so it
    # reports the capability the host's _adapter_gate requires. A helper that
    # does not implement it must NOT advertise it -- that is what keeps the
    # gate meaningful.
    $caps += 'adapter:electron'
    return $caps
}
$capabilities = Get-HelperCapabilities

# Issue #136: per-monitor DPI awareness so the helper's click points are
# PHYSICAL pixels. PROCESS-level declaration FIRST (the request dispatch
# runs on worker/child runspaces - a per-thread declaration on the main
# thread would not cover them); the per-monitor-V2 thread context on the
# serving thread is the refinement; the legacy system-DPI declaration is
# the last resort. The outcome rides session_state (dpi_aware, through
# the injected $dpiDeclared session variable) for honest disclosure when
# every declaration fails.
$dpiDeclared = $false
try { $dpiDeclared = ([HypervMcp.Uia.Native]::SetProcessDpiAwareness(2) -eq 0) } catch { }
try {
    $dpiCtx = New-Object IntPtr(-4)
    if ([HypervMcp.Uia.Native]::SetThreadDpiAwarenessContext($dpiCtx) -ne [IntPtr]::Zero) { $dpiDeclared = $true }
} catch { }
if (-not $dpiDeclared) {
    try { $dpiDeclared = [HypervMcp.Uia.Native]::SetProcessDPIAware() } catch { }
}

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
            try { $json = ($response | ConvertTo-Json -Compress -Depth 100) } catch { $json = '{"id":"","ok":false,"error_class":"helper_error","error":"response serialization failed"}' }
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
    'Get-ElementProcessName', 'ConvertTo-Condition', 'Resolve-Target',
    'Get-WindowScopeSet', 'New-WalkCache', 'Get-ElementIdScopeSelector',
    'Enter-Snapshot', 'Resolve-Ref', 'Get-HelperCapabilities',
    'Select-One', 'Get-ElementResult', 'Walk-Tree', 'Invoke-Pattern', 'Invoke-Request',
    'Get-SessionBlock',
    # Issue #129: the per-glyph run merge (the electron adapter's merge runs
    # INSIDE the per-request worker runspace, so its functions must be
    # injected there like every other verb helper).
    'Get-ElementName', 'Get-ElementLineY', 'Test-IsGlyphNode',
    'New-MergedGlyphElement', 'Merge-GlyphRuns'
)
$sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
foreach ($name in $functionNames) {
    $cmd = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        $sessionState.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($name, $cmd.Definition)))
    }
}
$sessionVariables = @{
    SnapshotStore = $script:SnapshotTables
    dpiDeclared = $dpiDeclared
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
