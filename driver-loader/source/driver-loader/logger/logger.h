#pragma once
#include <iostream>

namespace driver_loader::logger {
	inline void info(const std::string& message) {
		std::cout << "\033[36m[info]\033[0m " << message << std::endl;
	}

	inline void warn(const std::string& message) {
		std::cout << "\033[33m[warn]\033[0m " << message << std::endl;
	}

	inline void error(const std::string& message) {
		std::cout << "\033[31m[error]\033[0m " << message << std::endl;
	}
}
