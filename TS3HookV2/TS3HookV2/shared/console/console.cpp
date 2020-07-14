#include "../shared.h"

#define WIN32_LEAN_AND_MEAN

#include <windows.h>

namespace shared::console
{
	auto m_init = false;

	auto attach() -> void
	{
		if (m_init)
			return;

		auto is_console_allocated = AllocConsole();
		auto is_console_attached = AttachConsole(GetCurrentProcessId());

		FILE* dummy;
		freopen_s(&dummy, "CONOUT$", "wb", stdout);
        freopen_s(&dummy, "CONOUT$", "wb", stderr);
        freopen_s(&dummy,  "CONIN$", "r", stdin);

		SetConsoleTitleW(L"TS3HookV2");
		SetConsoleOutputCP(65001);

		m_init = is_console_allocated && is_console_attached;
	}

	auto detach() -> void
	{
		if (!m_init)
			return;

		fclose(stdout);
		fclose(stdin);

		FreeConsole();
		PostMessageW(GetConsoleWindow(), WM_CLOSE, NULL, NULL);
	}
}