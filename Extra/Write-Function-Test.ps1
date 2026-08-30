Clear-Host
Write-Host

$base = Resolve-DriverAddress -DriverName ntoskrnl.exe
$rva  = Resolve-SymbolFromPdb -FunctionName NtAddAtom
$Bind = Bind-KernelAddress -VA ([IntPtr]::Add($base, $rva))

if ($Bind -ne $null) {
    $TmpVA = [IntPtr]::Add($Bind.BaseVA, $Bind.ByteOffset)
    
    # 1. Read 16 bytes into a byte array
    $byteArray = New-Object byte[] 16
    [Marshal]::Copy($TmpVA, $byteArray, 0, 16)
    
    # 2. Print the array in Hex format
    Write-Host "[+] Read 16 bytes from NtAddAtom:" -ForegroundColor Green
    $hexString = ($byteArray | ForEach-Object { "{0:X2}" -f $_ }) -join " "
    Write-Host $hexString -ForegroundColor Cyan
    
    # 3. Write the exact same array back to the kernel address
    [Marshal]::Copy($byteArray, 0, $TmpVA, 16)
    Write-Host "[+] Successfully wrote the 16 bytes back!" -ForegroundColor Green
    
    Bind-KernelAddress -Package $Bind -Release
} else {
    Write-Host "[-] Failed to bind kernel address." -ForegroundColor Red
}