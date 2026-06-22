#pragma once
#include <Windows.h>
#include <cstdint>

namespace PGRHostControl {
    namespace codes {
        inline static constexpr DWORD MAP_PYHSICAL_MEMORY = 0x80102040;
        inline static constexpr DWORD UNMAP_PYHSICAL_MEMORY = 0x80102044;
    }

    struct MapReq {
        PVOID  Size;
        PVOID  PhysicalAddress;
        HANDLE Handle;
        PVOID  MappingAddress;
        PVOID  SectionObject;
    };

    class Driver {
    public:
        HANDLE hDevice = INVALID_HANDLE_VALUE;

        bool Open() {
            hDevice = CreateFileA("\\\\.\\PGRHostControl",
                GENERIC_READ | GENERIC_WRITE, 0, 0,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
            return hDevice != INVALID_HANDLE_VALUE;
        }

        void Close() {
            if (hDevice != INVALID_HANDLE_VALUE)
                CloseHandle(hDevice);
        }

        PVOID Map(ULONG_PTR physAddr, SIZE_T size, MapReq& req) {
            req = {};
            req.PhysicalAddress = (PVOID)physAddr;
            req.Size = (PVOID)size;
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(hDevice, codes::MAP_PYHSICAL_MEMORY,
                &req, sizeof(req),
                &req, sizeof(req),
                &bytes, NULL);
            if (!ok || bytes != sizeof(req) || !req.MappingAddress)
                return nullptr;
            return req.MappingAddress;
        }

        void Unmap(MapReq& req) {
            DWORD bytes = 0;
            DeviceIoControl(hDevice, codes::UNMAP_PYHSICAL_MEMORY,
                &req, sizeof(req),
                &req, sizeof(req),
                &bytes, NULL);
        }

        bool Read(ULONG_PTR physAddr, PVOID buffer, SIZE_T size) {
            // align down to page
            ULONG_PTR alignedPA = physAddr & ~0xFFFULL;
            SIZE_T offset = physAddr - alignedPA;
            SIZE_T mapSize = offset + size;
            // round up to page
            mapSize = (mapSize + 0xFFF) & ~0xFFFULL;

            MapReq req{};
            PVOID mapped = Map(alignedPA, mapSize, req);
            if (!mapped) return false;

            memcpy(buffer, (BYTE*)mapped + offset, size);
            Unmap(req);
            return true;
        }

        bool Read8(ULONG_PTR physAddr, ULONG64& out) {
            return Read(physAddr, &out, 8);
        }

        bool Write(ULONG_PTR physAddr, const void* buffer, SIZE_T size)
        {
            // align down to page
            ULONG_PTR alignedPA = physAddr & ~0xFFFULL;
            SIZE_T offset = physAddr - alignedPA;
            SIZE_T mapSize = offset + size;

            // round up to page
            mapSize = (mapSize + 0xFFF) & ~0xFFFULL;

            MapReq req{};
            PVOID mapped = Map(alignedPA, mapSize, req);

            if (!mapped)
                return false;

            memcpy(
                (BYTE*)mapped + offset,
                buffer,
                size
            );

            Unmap(req);
            return true;
        }
    };
}