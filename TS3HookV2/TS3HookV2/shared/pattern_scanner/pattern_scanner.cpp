#include "../shared.h"

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <vector>

namespace shared::pattern_scanner
{
	auto scan(std::string_view module_name, std::string_view pattern, std::string_view mask, std::int32_t offset) -> std::uintptr_t
	{
		MODULEINFO module_info = { nullptr };
		K32GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(module_name.data()), &module_info, sizeof(MODULEINFO));

		const auto start_address = reinterpret_cast<std::uint8_t*>(module_info.lpBaseOfDll);
		const auto end_address = start_address + module_info.SizeOfImage;

		auto signature = std::vector<std::pair<std::uint8_t, bool>>{};
		for (auto i = 0; i < mask.length(); i++)
			signature.emplace_back(pattern[i], mask[i] == 'x');

		const auto ret = std::search(start_address, end_address, signature.begin(), signature.end(),
			[](std::uint8_t byte, std::pair<std::uint8_t, bool> sig)
			{
				return !sig.second || byte == sig.first;
			});

		return ret == end_address ? 0 : std::uintptr_t(ret + offset);
	}
}