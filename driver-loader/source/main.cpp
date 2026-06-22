#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <exception>

#include "driver-loader/driver-loader.h"

int main()
{
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

	DWORD mode = 0;
	GetConsoleMode(hOut, &mode);

	mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, mode);

    driver_loader::load();

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
}