Clear-Host
Write-Host

########################

Stop-Process -Name "ConsoleAppTest" -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

# Locate MSVC environment script cleanly (fixed space bug)
$vcvars = "Community", "Professional", "Enterprise" | ForEach-Object {
    "C:\Program Files\Microsoft Visual Studio\2022\$_\VC\Auxiliary\Build\vcvars64.bat"
} | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $vcvars) { Write-Error "[-] MSVC vcvars64.bat not found."; return }

$cppCode = @'
#include <iostream>
#include <windows.h>
#include <string>

int main() {
    char buffer[32] = "Hello World!";
    do {
        std::string currentText(buffer);
        if (currentText == "Hello World!") {
            std::cout << "[*] Status: Original text intact (" << currentText << ")\n";
        } else {
            std::cout << "[+] Status: Buffer modified! Current value: " << currentText << "\n";
        }
        Sleep(1000);
    } while (true);
}
'@

$sourcePath = Join-Path $env:TEMP "$([Guid]::NewGuid()).cpp"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$outputPath = Join-Path $scriptDir "ConsoleAppTest.exe"

Set-Content -Path $sourcePath -Value $cppCode -Encoding UTF8
Write-Host "[*] Compiling..." -ForegroundColor Yellow

& cmd.exe /c "`"$vcvars`" x64 && cl.exe /O2 /EHsc `"$sourcePath`" /Fe:`"$outputPath`" /link /DYNAMICBASE /HIGHENTROPYVA" 2>&1 | Out-Null
Remove-Item $sourcePath -ErrorAction SilentlyContinue

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Built: $outputPath" -ForegroundColor Green
} else {
    Write-Host "[-] Build failed: $LASTEXITCODE" -ForegroundColor Red
}

########################

# 1. Allocate buffers for STARTUPINFO (104 bytes) and PROCESS_INFORMATION (24 bytes)
$exePath = $outputPath
$siPtr = New-IntPtr -Size 104 -InitialValue 0 -ValueType int
$piPtr = New-IntPtr -Size 24  -InitialValue 0 -ValueType int

# 2. Invoke CreateProcessW with CREATE_SUSPENDED (0x4) + CREATE_NEW_CONSOLE (0x10) = 0x14
$creationFlags = 0x00000004 -bor 0x00000010 # 0x14
$Values  = $exePath, 0L, 0L, 0L, 0, $creationFlags, 0L, 0L, $siPtr, $piPtr
$success = Invoke-UnmanagedMethod -Dll "kernel32.dll" -Function "CreateProcessW" -Values $Values

if ($success -eq 0) {
    Write-Host "[-] Failed to create suspended process." -ForegroundColor Red
    return
}

# 3. Read the Process ID and handles out of the PROCESS_INFORMATION structure
$hProcess = [Marshal]::ReadIntPtr($piPtr, 0)
$hThread  = [Marshal]::ReadIntPtr($piPtr, 8)
$ProcID   = [Marshal]::ReadInt32($piPtr, 16)

try {

    Start-Sleep -Milliseconds 200

    Write-Host "[+] Process started suspended. PID: $ProcID" -ForegroundColor Cyan
    Start-Sleep -Milliseconds 200

    $ProcPEB   = (Query-Process -ProcessId $ProcID).PebBaseAddress
    $imageBase = [BitConverter]::ToInt64((Invoke-MemoryRead -ProcessId $ProcID -Address ([Int64]$ProcPEB + 0x10) -BytesToRead 8), 0)

    $targetString = "Hello World!"
    $maxScan      = 0x1000000 # 16 MB search ceiling
    $chunkSize    = 0x1000    # Strict 4 KB (4096 bytes) pages
    $memoryStream = New-Object System.IO.MemoryStream

    Write-Host "[*] Reading and stitching 4KB memory pages..." -ForegroundColor Yellow

    for ($offset = 0; $offset -lt $maxScan; $offset += $chunkSize) {
        try {
            $buf = Invoke-MemoryRead -ProcessId $ProcID -Address ([IntPtr]([Int64]$imageBase + $offset)) -BytesToRead $chunkSize
            if ($buf) {
                $memoryStream.Write($buf, 0, $buf.Length)
            } else {
                $zeroes = New-Object byte[] $chunkSize
                $memoryStream.Write($zeroes, 0, $zeroes.Length)
            }
        } catch {
            $zeroes = New-Object byte[] $chunkSize
            $memoryStream.Write($zeroes, 0, $zeroes.Length)
        }
    }

    $FindPatternBlock = {
        param(
            [byte[]]$AllBytes,
            [string]$TargetString
        )

        $targetBytes = [Text.Encoding]::ASCII.GetBytes($TargetString)
        $foundOffset = -1

        if ($AllBytes.Length -ge $targetBytes.Length) {
            $firstByte = $targetBytes[0]
            $maxIndex = $AllBytes.Length - $targetBytes.Length
            $index = 0

            while ($index -le $maxIndex) {
                $index = [Array]::IndexOf($AllBytes, $firstByte, $index, ($maxIndex - $index + 1))
                if ($index -eq -1) { break }

                $match = $true
                for ($i = 1; $i -lt $targetBytes.Length; $i++) {
                    if ($AllBytes[$index + $i] -ne $targetBytes[$i]) {
                        $match = $false
                        break
                    }
                }

                if ($match) {
                    $foundOffset = $index
                    break
                }
                $index++
            }
        }
    
        return $foundOffset
    }

    # --- How to call it ---
    $allBytes = $memoryStream.ToArray()
    $memoryStream.Dispose()

    $foundOffset = & $FindPatternBlock -AllBytes $allBytes -TargetString $targetString

    if ($foundOffset -lt 0) {
        Write-Host "[-] String not found in memory blob." -ForegroundColor Red
        return
    }

    $VA = [IntPtr]([Int64]$imageBase + $foundOffset)
    $PA = Resolve-DirectoryTable -VA64 $VA -ProcessID $ProcID

    Write-Host "[+] Successfully located target at VA: 0x$($VA.ToString('X'))" -ForegroundColor Green

    Write-Host
    [string]::Format("Value From PA Address : {0}", ([Text.Encoding]::ASCII.GetString([byte[]](Read-KernelAddress -PA $PA -Size 16))))    

    $bytes = [byte[]]::new(16)
    [Text.Encoding]::ASCII.GetBytes("GotYa!`r").CopyTo($bytes, 0)

    try {
        $MapObj = Map-KernelMemory `
            -PA $PA -Size 20 `
            -Mode gibepext `
            -CacheType MmCached
        if ($MapObj.MappedAddress -ne 0) {
            Write-VirtualAddress `
                -VA $MapObj.MappedAddress `
                -Value $bytes | Out-Null
            Write-Host "[+] Successfully patched memory!" -ForegroundColor Green
        } else {
            $MapObj = Map-KernelMemory `
                -PA $PA -Size 20 `
                -Mode gibepext `
                -CacheType MmNonCached
            if ($MapObj.MappedAddress -ne 0) {
                Write-VirtualAddress `
                    -VA $MapObj.MappedAddress `
                    -Value $bytes | Out-Null
                Write-Host "[+] Successfully patched memory!" -ForegroundColor Green
            } else {
                Write-Host "[+] Failed to patch the memory!" -ForegroundColor Red
            }
        }
    } finally {
        Free-IntPtr `
            -handle $MapObj.Device `
            -Method NtHandle
    }

} finally {

    $Values = $hThread, 0L
    Invoke-UnmanagedMethod -Dll "ntdll.dll" -Function "NtResumeThread" -Values $Values | Out-Null

    Free-IntPtr $siPtr -Method NtHandle
    Free-IntPtr $piPtr -Method NtHandle

    Write-Host "[+] Process resumed and running!" -ForegroundColor Green
}