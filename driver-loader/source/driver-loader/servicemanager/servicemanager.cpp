#include "servicemanager.h"

#include <Windows.h>
#include <stdexcept>
#include <string>

#include "../logger/logger.h"

namespace driver_loader::servicemanager {
	class ServiceManager {
	public:
		ServiceManager() {
			scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);

			if (!scm) {
				DWORD error = GetLastError();
				throw std::runtime_error("OpenSCManagerA failed: " + std::to_string(error));
			}
		}

		~ServiceManager() {
			if (scm) {
				CloseServiceHandle(scm);
			}
		}

		SC_HANDLE get() const {
			return scm;
		}

		ServiceManager(const ServiceManager&) = delete;
		ServiceManager& operator=(const ServiceManager&) = delete;

	private:
		SC_HANDLE scm = nullptr;
	};

	void loadDriver(std::string name, LPCSTR path) {
		ServiceManager scm{};

		SC_HANDLE service = OpenServiceA(
			scm.get(),
			name.c_str(),
			SERVICE_START | SERVICE_STOP | DELETE);

		if (!service) {
			if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
				service = CreateServiceA(
					scm.get(),
					name.c_str(),
					name.c_str(),
					SERVICE_START | SERVICE_STOP | DELETE,
					SERVICE_KERNEL_DRIVER,
					SERVICE_DEMAND_START,
					SERVICE_ERROR_NORMAL,
					path,
					nullptr, nullptr, nullptr, nullptr, nullptr);

				if (!service)
					throw std::runtime_error("CreateService failed: " + std::to_string(GetLastError()));
			}
			else {
				throw std::runtime_error("OpenServiceA failed: " + std::to_string(GetLastError()));
			}
		}

		bool already_running = false;

		if (!StartServiceA(service, 0, nullptr)) {
			DWORD error = GetLastError();
			if (error == ERROR_SERVICE_ALREADY_RUNNING)
				already_running = true;
			else {
				CloseServiceHandle(service);
				throw std::runtime_error("StartServiceA failed: " + std::to_string(error));
			}
		}

		if (service)
			CloseServiceHandle(service);

		if (already_running)
			logger::warn(name + " service was already running.");
		else
			logger::info("Loaded " + name + " driver.");
	}

	void unloadDriver(std::string name) {
		ServiceManager scm{};

		SC_HANDLE service = OpenServiceA(
			scm.get(),
			name.c_str(),
			SERVICE_START | SERVICE_STOP | DELETE);

		if (!service)
		{
			DWORD error = GetLastError();
			if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
				return;
			}

			throw std::runtime_error("OpenServiceA failed: " + std::to_string(error));
		}

		SERVICE_STATUS status{};
		if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
		{
			DWORD error = GetLastError();
			if (error != ERROR_SERVICE_NOT_ACTIVE)
			{
				CloseServiceHandle(service);
				throw std::runtime_error("ControlService STOP failed: " + std::to_string(error));
			}
		}

		if (!DeleteService(service))
		{
			DWORD error = GetLastError();
			CloseServiceHandle(service);
			throw std::runtime_error("DeleteService failed: " + std::to_string(error));
		}

		CloseServiceHandle(service);

		logger::info("Unloaded vulnerable driver");
	}

	void loadVulnerableDriver() {
		loadDriver("PGRHostControl", "C:\\Users\\michael\\development\\sablewtf\\driver-loader\\PGRHostControl64.sys");
	}

	void unloadVulnerableDriver() {
		unloadDriver("PGRHostControl");
	}

	void loadTargetDriver() {
		loadDriver("sable-driver", "C:\\Users\\michael\\development\\sablewtf\\driver-loader\\MyDriver1.sys");
	}
}