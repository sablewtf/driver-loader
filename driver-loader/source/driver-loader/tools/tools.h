#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <optional>

#include "../pgrhostcontrol/pgrhostcontrol.h"

namespace driver_loader::tools {
	bool EnableDebugPrivilege();

	uint64_t GetMaxPhysicalMemory();
	uint64_t GetNtoskrnkVirtualAddress();
	std::string toHexString(uint64_t value);

	uint64_t VirtualToPhysical(uint64_t cr3, uint64_t virtualAddress);
	uint64_t FindCR3();

	std::optional<std::pair<uint64_t, uint64_t>> ResolveKernelOffsetsStrict();

	std::string wstring_to_string(const std::wstring& wstr);
}