#pragma once

#include "pgrhostcontrol/pgrhostcontrol.h"

namespace driver_loader::globals {
	inline PGRHostControl::Driver driver;

	inline uint64_t maxPhysicalMemory;
	inline uint64_t ntoskrnlVirtualAddress;
	inline uint64_t cr3;
}