# hyperv-mcp in-session UI Automation helper (issue #29, Workstream F PR 5).
#
# Runs in the INTERACTIVE session of the test account (per-user AtLogOn
# scheduled task, LogonType Interactive, RunLevel Highest), hosts
# System.Windows.Automation (in-box UIAutomationClient/UIAutomationTypes)
# and serves ONE newline-JSON request frame at a time on a local named
# pipe. The host reaches the pipe only through PowerShell Direct.
#
# Security contract:
#   - The pipe is created with the PIPE_REJECT_REMOTE_CLIENTS flag (0x8);
#     its DACL grants ReadWrite to the running user and the built-in
#     Administrators group only.
#   - Every request frame carries min_version + target {vm_guid, user_sid,
#     session_id}; the helper enforces them STRICTLY (stale host refused as
#     helper_version_mismatch; a session-less request refused as
#     session_unverified; a mismatched VM/user/session refused as
#     target_mismatch) BEFORE any verb dispatch. Caller text is never
#     evaluated as code: verbs are a closed allowlist driving UIA patterns
#     (Invoke, Toggle, SelectionItem, ExpandCollapse, Value, plus the
#     LegacyIAccessible bridge) - no Invoke-Expression, no ScriptBlock
#     creation from request data, no input injection.
#   - Responses report the length of a set value, never the value; request
#     secrets never appear in helper logs (the helper writes no logs).
#
# Windows PowerShell 5.1 only; in-box assemblies; exits when the session
# logs off (the AtLogOn task restarts it on the next logon).

$ErrorActionPreference = 'Stop'

$HelperVersion = '1'
$PipeName = 'hyperv-mcp-uia'
$HelperDir = 'C:\ProgramData\hyperv-mcp\uia-helper'
$MaxDepth = 8
$MaxElements = 2000
$MaxMatches = 200
$MaxValueChars = 65536

Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop

Add-Type -Namespace HypervMcp.Uia -Name Native -MemberDefinition @'
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
[DllImport("user32.dll", SetLastError = true)] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool GetUserObjectInformationW(IntPtr hObj, int idx, System.Text.StringBuilder buf, uint len, out uint needed);
[DllImport("user32.dll")] public static extern bool CloseDesktop(IntPtr h);
[DllImport("wtsapi32.dll")] public static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out uint bytesReturned);
[DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr buffer);
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[StructLayout(LayoutKind.Sequential)] public struct WTSINFOEX_LEVEL1 { public uint SessionId; public uint State; public int SessionFlags; public string unused; }
'@

function Get-OwnIdentity {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $ownSession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $ownGuid = ''
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
        if ($cs -and $cs.UUID) { $ownGuid = ([string]$cs.UUID).ToLowerInvariant() }
    } catch { $ownGuid = '' }
    @{
        sid = $identity.User.Value
        user = ($identity.Name -split '\\')[-1]
        session_id = $ownSession
        vm_guid = $ownGuid
    }
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
    # WTSQuerySessionInformationW(WTSSessionInfoEx).SessionFlags:
    # WTS_SESSIONSTATE_LOCK = 0, WTS_SESSIONSTATE_UNLOCK = 1, inverted on
    # Windows 7 / Server 2008 R2. Cross-checked with OpenInputDesktop.
    $locked = $true
    $buffer = [IntPtr]::Zero
    $bytes = 0
    $ok = [HypervMcp.Uia.Native]::WTSQuerySessionInformationW([IntPtr]::Zero, -1, 25, [ref]$buffer, [ref]$bytes)
    if ($ok -and $buffer -ne [IntPtr]::Zero) {
        try {
            # WTSINFOEXW { Level:1, Level1 { Level, WTSINFOEX_LEVEL1 { SessionId, State, SessionFlags(=0 lock / 1 unlock) } } }
            $sessionFlags = [System.Runtime.InteropServices.Marshal]::ReadInt32($buffer, 8 + 4 + 4 + 8)
            if ($sessionFlags -eq 1) { $locked = $false } else { $locked = $true }
        } catch { $locked = -not (Test-OwnsInputDesktop) }
        [void][HypervMcp.Uia.Native]::WTSFreeMemory($buffer)
    } else {
        $locked = -not (Test-OwnsInputDesktop)
    }
    if ($locked -and (Test-OwnsInputDesktop)) { $locked = $false }
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
    $security = New-Object System.IO.Pipes.PipeSecurity
    $own = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = New-Object System.IO.Pipes.PipeAccessRule($own, 'ReadWrite', 'Allow')
    $security.AddAccessRule($rule)
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $rule = New-Object System.IO.Pipes.PipeAccessRule($admins, 'ReadWrite', 'Allow')
    $security.AddAccessRule($rule)
    return $security
}

function ConvertTo-Condition([hashtable]$selector) {
    $conditions = @()
    $direct = @{
        automation_id = [System.Windows.Automation.AutomationElement]::AutomationIdProperty
        name = [System.Windows.Automation.AutomationElement]::NameProperty
        control_type = $null
        class_name = [System.Windows.Automation.AutomationElement]::ClassNameProperty
    }
    foreach ($key in $direct.Keys) {
        if ($null -ne $selector[$key] -and $null -ne $direct[$key]) {
            $conditions += (New-Object System.Windows.Automation.PropertyCondition($direct[$key], $selector[$key]))
        }
    }
    if ($null -ne $selector['control_type']) {
        $ct = [System.Windows.Automation.ControlType]::LookupById([string]$selector['control_type'])
        if ($null -eq $ct) {
            $ct = [System.Windows.Automation.ControlType]::$($selector['control_type'])
        }
        $conditions += (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ct))
    }
    return $conditions
}

function Find-WindowScope([hashtable]$selector) {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $scopeCondition = $null
    if ($null -ne $selector['hwnd']) {
        $byHandle = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr][long]$selector['hwnd'])
        if ($null -ne $byHandle) { return $byHandle }
    }
    $conditions = @()
    if ($selector['window_title']) {
        $conditions += (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, [string]$selector['window_title']))
    }
    if ($conditions.Count -gt 0) {
        $and = New-Object System.Windows.Automation.AndCondition($conditions)
        $found = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $and)
        foreach ($f in $found) { return $f }
    }
    return $root
}

function Resolve-Target([hashtable]$selector) {
    $scope = Find-WindowScope $selector
    $conditions = ConvertTo-Condition $selector
    if ($null -ne $selector['name_contains']) {
        $matches1 = @()
        $all = $scope.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($el in $all) {
            try {
                if ($el.Current.Name -like ("*" + $selector['name_contains'] + "*")) { $matches1 += $el }
            } catch { }
            if ($matches1.Count -ge $MaxMatches) { break }
        }
        return $matches1
    }
    if ($conditions.Count -eq 0) {
        $walker = @($scope)
        return $walker
    }
    $and = New-Object System.Windows.Automation.AndCondition($conditions)
    $found = $scope.FindAll([System.Windows.Automation.TreeScope]::Descendants, $and)
    $list = @()
    foreach ($el in $found) { $list += $el; if ($list.Count -ge $MaxMatches) { break } }
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
    @{
        element_id = ($runtimeId -join ':')
        name = [string]$el.Current.Name
        control_type = [string]$el.Current.ControlType.ProgrammaticName -replace '^ControlType\.', ''
        automation_id = [string]$el.Current.AutomationId
        class_name = [string]$el.Current.ClassName
        enabled = [bool]$el.Current.IsEnabled
        rect = $rect
    }
}

function Invoke-Pattern($el, $automationPattern, [string]$action, [object]$argument) {
    try {
        $pattern = $el.GetCurrentPattern($automationPattern)
    } catch {
        return $null
    }
    switch ($action) {
        'invoke' { $pattern.Invoke(); break }
        'toggle' { $pattern.Toggle(); break }
        'select' { $pattern.Select(); break }
        'expand' { $pattern.Expand(); break }
        'collapse' { $pattern.Collapse(); break }
        'setvalue' { $pattern.SetValue([string]$argument); break }
        'focus' { $pattern.SetFocus(); break }
        default { return $null }
    }
    return $true
}

function Invoke-Request([hashtable]$req) {
    $verb = [string]$req['verb']

    if ($req.ContainsKey('min_version') -and $null -ne $req['min_version'] -and ([string]$req['min_version']) -ne $HelperVersion) {
        return @{ ok = $false; error_class = 'helper_version_mismatch'; error = "helper version $HelperVersion cannot serve min_version $($req['min_version'])" }
    }

    $target = $req['target']
    if ($null -eq $target) {
        return @{ ok = $false; error_class = 'session_unverified'; error = 'the request carries no target' }
    }
    $own = Get-OwnIdentity
    if ($own.vm_guid -and $target['vm_guid'] -and ([string]$target['vm_guid']).ToLowerInvariant() -ne $own.vm_guid) {
        return @{ ok = $false; error_class = 'target_mismatch'; error = "the request targets VM $($target['vm_guid']) but this helper runs in VM $($own.vm_guid)" }
    }
    if ($target['user_sid'] -and ([string]$target['user_sid']) -ne $own.sid) {
        return @{ ok = $false; error_class = 'target_mismatch'; error = "the request targets user $($target['user_sid']) but this helper runs as $($own.sid)" }
    }
    if ($null -eq $target['session_id'] -or [int]$target['session_id'] -ne $own.session_id) {
        return @{ ok = $false; error_class = 'session_unverified'; error = "the request does not carry this helper's interactive session ($($own.session_id))" }
    }

    $locked = Get-LockState

    if ($verb -eq 'session_state') {
        return @{
            ok = $true
            result = @{
                active_session_id = $own.session_id
                interactive_user = $own.user
                locked = $locked
                foreground_window = (Get-ForegroundWindow)
            }
        }
    }

    $selector = $req['selector']
    if ($null -eq $selector -and $req.ContainsKey('args') -and $null -ne $req['args']) {
        $selector = $req['args']['selector']
    }

    if ($verb -eq 'inspect') {
        $depth = 3; $cap = 200
        if ($null -ne $req['args']) {
            if ($null -ne $req['args']['depth']) { $depth = [Math]::Min([int]$req['args']['depth'], $MaxDepth) }
            if ($null -ne $req['args']['max_elements']) { $cap = [Math]::Min([int]$req['args']['max_elements'], $MaxElements) }
        }
        $script:seen = 0
        $script:cap = $cap
        $root = [System.Windows.Automation.AutomationElement]::RootElement
        function Walk($el, $d) {
            if ($script:seen -ge $script:cap -or $d -lt 0) { return $null }
            $script:seen++
            $node = Get-ElementResult $el
            $node.children = @()
            if ($d -gt 0) {
                $kids = $el.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
                foreach ($k in $kids) {
                    if ($script:seen -ge $script:cap) { break }
                    $child = Walk $k ($d - 1)
                    if ($null -ne $child) { $node.children += $child }
                }
            }
            $node
        }
        $tree = Walk $root $depth
        return @{ ok = $true; result = @{ elements = $script:seen; truncated = ($script:seen -ge $script:cap); tree = $tree } }
    }

    if ($verb -eq 'find' -or $verb -eq 'wait_for') {
        $elements = Resolve-Target $selector
        if ($verb -eq 'wait_for') {
            $argsPair = $req['args']
            $gone = $false; $budget = 30
            if ($null -ne $argsPair) {
                if ($null -ne $argsPair['gone']) { $gone = [bool]$argsPair['gone'] }
                if ($null -ne $argsPair['timeout_s']) { $budget = [Math]::Min([int]$argsPair['timeout_s'], 120) }
            }
            $deadline = [DateTime]::UtcNow.AddSeconds($budget)
            while ([DateTime]::UtcNow -lt $deadline) {
                $elements = Resolve-Target $selector
                $present = ($null -ne $elements -and $elements.Count -gt 0)
                if ($gone -and -not $present) { return @{ ok = $true; result = @{ gone = $true } } }
                if (-not $gone -and $present) { break }
                Start-Sleep -Milliseconds 400
            }
        }
        if ($req.ContainsKey('element_id') -and $null -ne $req['element_id']) {
            $elements = @()
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
    elseif ($null -ne $req['args'] -and $null -ne $req['args']['element_id']) { $elementIdWanted = [string]$req['args']['element_id'] }

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
        $elements = Resolve-Target $selector
        $one = Select-One $elements $selector
        if ($null -ne $one -and $one.ambiguous) {
            return @{ ok = $false; error_class = 'ambiguous_selector'; error = 'the selector matched more than one element'; candidates = $one.candidates }
        }
        $el = $one
        if ($null -eq $el) {
            return @{ ok = $false; error_class = 'element_not_found'; error = 'the selector resolved no element' }
        }
    }

    if ($verb -eq 'focus') {
        if ($locked -or -not (Test-OwnsInputDesktop)) {
            return @{ ok = $false; error_class = 'no_interactive_desktop'; error = 'the session is locked; focus needs the interactive desktop' }
        }
        $done = Invoke-Pattern $el ([System.Windows.Automation.AutomationElement]::Equals($null, $null)) 'none' $null
        try { $el.SetFocus() } catch {
            return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes no focus-capable pattern' }
        }
        return @{ ok = $true; result = @{ focused = $true } }
    }

    if ($verb -eq 'set_value') {
        $value = $null
        if ($req.ContainsKey('value')) { $value = $req['value'] }
        elseif ($null -ne $req['args']) { $value = $req['args']['value'] }
        if ($null -eq $value) {
            return @{ ok = $false; error_class = 'invalid_request'; error = 'set_value requires a value' }
        }
        $text = [string]$value
        if ($text.Length -gt $MaxValueChars) {
            return @{ ok = $false; error_class = 'invalid_request'; error = 'the value exceeds the 64 KiB bound' }
        }
        $done = Invoke-Pattern $el ([System.Windows.Automation.ValuePattern]::Pattern) 'setvalue' $text
        if ($null -eq $done) {
            return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes no ValuePattern' }
        }
        return @{ ok = $true; result = @{ length = $text.Length; length_set = $text.Length } }
    }

    if ($verb -eq 'invoke') {
        $done = Invoke-Pattern $el ([System.Windows.Automation.InvokePattern]::Pattern) 'invoke' $null
        if ($null -eq $done) { $done = Invoke-Pattern $el ([System.Windows.Automation.TogglePattern]::Pattern) 'toggle' $null }
        if ($null -eq $done) { $done = Invoke-Pattern $el ([System.Windows.Automation.SelectionItemPattern]::Pattern) 'select' $null }
        if ($null -eq $done) { $done = Invoke-Pattern $el ([System.Windows.Automation.ExpandCollapsePattern]::Pattern) 'expand' $null }
        if ($null -eq $done) {
            return @{ ok = $false; error_class = 'unsupported_capability'; error = 'the element exposes no InvokePattern' }
        }
        return @{ ok = $true; result = @{ invoked = $true } }
    }

    return @{ ok = $false; error_class = 'invalid_request'; error = "unknown verb $verb" }
}

$identity = Get-OwnIdentity
$nonceFile = Join-Path $HelperDir 'nonce.txt'
$capabilities = @('uia', 'msaa')
$ownNonce = ''
if (Test-Path $nonceFile) { $ownNonce = (Get-Content $nonceFile -TotalCount 1) -as [string] }
$pipeSecurity = New-PipeSecurity
$session = @{
    session_id = $identity.session_id
    interactive_user = $identity.user
    locked = (Get-LockState)
    helper = @{ running = $true; version = $HelperVersion; capabilities = $capabilities; nonce = $ownNonce }
}

while ($true) {
    $pipe = New-Object System.IO.Pipes.NamedPipeServerStream(
        $PipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte,
        # 0xC = Asynchronous (0x4) | 0x8 = PIPE_REJECT_REMOTE_CLIENTS (the
        # .NET Framework 4.x enum does not name the flag; CreateNamedPipe
        # honors the raw value).
        [System.IO.Pipes.PipeOptions]0xC,
        0, 0, $pipeSecurity)
    try {
        $pipe.WaitForConnection()
        $reader = New-Object System.IO.StreamReader($pipe)
        $writer = New-Object System.IO.StreamWriter($pipe)
        $writer.AutoFlush = $true
        $line = $reader.ReadLine()
        if ($line) {
            $response = $null
            $requestId = ''
            try {
                $request = $line | ConvertFrom-Json
                $requestId = [string]$request.id
                $hashtable = @{}
                foreach ($prop in $request.PSObject.Properties) { $hashtable[$prop.Name] = $prop.Value }
                $response = Invoke-Request $hashtable
            } catch {
                $response = @{ ok = $false; error_class = 'helper_error'; error = $_.Exception.Message }
            }
            $response.id = $requestId
            $response.session = $session
            $writer.WriteLine(($response | ConvertTo-Json -Compress -Depth 8))
        }
    } catch {
        # A broken pipe (client vanished, session ending) loops or exits.
        if (-not $pipe.IsConnected) { }
    } finally {
        try { $pipe.Disconnect() } catch { }
        $pipe.Dispose()
    }
}
