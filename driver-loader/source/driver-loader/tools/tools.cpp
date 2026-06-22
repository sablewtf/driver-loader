#include "tools.h"
#include <winternl.h>
#include <sstream>
#include <iomanip>
#include <string>

#include "../nt.h"
#include "../globals.h"
#include "../logger/logger.h"
#include "../symboldownloader/symboldownloader.h"

namespace driver_loader::tools {
    bool EnableDebugPrivilege()
    {
        HANDLE token;

        if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &token))
        {
            return false;
        }

        TOKEN_PRIVILEGES tp{};
        LUID luid;

        if (!LookupPrivilegeValue(
            nullptr,
            SE_DEBUG_NAME,
            &luid))
        {
            CloseHandle(token);
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(
            token,
            FALSE,
            &tp,
            sizeof(tp),
            nullptr,
            nullptr);

        DWORD err = GetLastError();

        CloseHandle(token);

        return err == ERROR_SUCCESS;
    }
	
	uint64_t GetMaxPhysicalMemory() {
		MEMORYSTATUSEX ms{ .dwLength = sizeof(ms) };
		GlobalMemoryStatusEx(&ms);
		uint64_t maxPhys = ms.ullTotalPhys;

		return maxPhys;
	}

	uint64_t GetNtoskrnkVirtualAddress() {
		ULONG size = 0;
		NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &size);
		auto buf = (RTL_PROCESS_MODULES*)malloc(size);
		NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, buf, size, &size);
		uint64_t va = (uint64_t)buf->Modules[0].ImageBase;
		free(buf);

		return va;
	}

	std::string toHexString(uint64_t value)
	{
		std::ostringstream oss;
		oss << "0x"
			<< std::hex
			<< std::setfill('0')
			<< value;

		return oss.str();
	}

    uint64_t VirtualToPhysical(uint64_t cr3, uint64_t virtualAddress) {
        uint64_t pml4e = 0, pdpte = 0, pde = 0, pte = 0;

        globals::driver.Read8(cr3 + ((virtualAddress >> 39) & 0x1FF) * 8, pml4e);
        if (!(pml4e & 1)) return 0;

        globals::driver.Read8((pml4e & 0x000FFFFFFFFFF000ULL) + ((virtualAddress >> 30) & 0x1FF) * 8, pdpte);
        if (!(pdpte & 1)) return 0;
        if (pdpte & (1ULL << 7))
            return (pdpte & 0x000FFFFFC0000000ULL) + (virtualAddress & 0x3FFFFFFF);

        globals::driver.Read8((pdpte & 0x000FFFFFFFFFF000ULL) + ((virtualAddress >> 21) & 0x1FF) * 8, pde);
        if (!(pde & 1)) return 0;
        if (pde & (1ULL << 7))
            return (pde & 0x000FFFFFFFE00000ULL) + (virtualAddress & 0x1FFFFF);

        globals::driver.Read8((pde & 0x000FFFFFFFFFF000ULL) + ((virtualAddress >> 12) & 0x1FF) * 8, pte);
        if (!(pte & 1)) return 0;

        return (pte & 0x000FFFFFFFFFF000ULL) + (virtualAddress & 0xFFF);
    }

    uint64_t FindCR3() {
        uint64_t pml4Index = (globals::ntoskrnlVirtualAddress >> 39) & 0x1FF;

        for (uint64_t pa = 0x1000; pa < globals::maxPhysicalMemory; pa += 0x1000) {
            uint64_t pml4e = 0;
            globals::driver.Read8(pa + pml4Index * 8, pml4e);
            if (!(pml4e & 1)) continue;
            if (pml4e & 0xFFFF000000000000ULL) continue;
            uint64_t pdptPA = pml4e & 0x000FFFFFFFFFF000ULL;
            if (!pdptPA || pdptPA >= globals::maxPhysicalMemory) continue;

            uint64_t physBase = VirtualToPhysical(pa, globals::ntoskrnlVirtualAddress);
            if (!physBase || physBase >= globals::maxPhysicalMemory) continue;

            USHORT mz = 0;
            globals::driver.Read(physBase, &mz, 2);
            if (mz != 0x5A4D) continue;

            return pa;
        }
        return 0;
    }

    std::optional<std::pair<uint64_t, uint64_t>> ResolveKernelOffsetsStrict() {
        SymbolDownloader symbolDownloader;
        symbolDownloader.Initialize();
        
        WCHAR systemRoot[MAX_PATH];
        GetSystemDirectoryW(systemRoot, MAX_PATH);
        std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";

        logger::info("Resolving ntosknrl offsets");

        // Get PDB GUID from current ntoskrnl.exe
        auto [pdbName, pdbGuid] = symbolDownloader.GetPdbInfoFromPe(ntoskrnlPath);
        if (pdbGuid.empty()) {
            logger::error("Failed to extract PDB GUID from ntoskrnl.exe");
            return std::nullopt;
        }

        logger::info("Current kernel PDB GUID: " + tools::wstring_to_string(pdbGuid));

        // Ensure symbols exist in ProgramData store (download if needed)
        if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) {
            logger::error("Failed to obtain PDB symbols");
            return std::nullopt;
        }

        // Resolve symbols from PDB
        auto seCiOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"SeCiCallbacks");
        auto zwOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"ZwFlushInstructionCache");

        if (!seCiOpt || !zwOpt) {
            logger::error("Failed to resolve required symbols from PDB");
            return std::nullopt;
        }

        return std::make_pair(*seCiOpt, *zwOpt);
    }

    std::string wstring_to_string(const std::wstring& wstr) {
        if (wstr.empty()) return {};
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, result.data(), size, nullptr, nullptr);
        return result;
    }
}