#include "../shared.h"

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdexcept>
#include <array>

namespace shared::detour
{
	constexpr auto m_shellcode = std::array<std::uint8_t, 6>
	{
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00
	};

	auto apply(std::byte* src, std::byte* dst, const std::size_t length) -> bool
	{
		if (length < 14)
			throw std::runtime_error("Length cannot be smaller than 14");

		DWORD old_prot;
		if (!VirtualProtect(src, length, PAGE_EXECUTE_READWRITE, &old_prot))
			return false;

		std::memcpy(src, m_shellcode.data(), m_shellcode.size());
		std::memcpy(src + m_shellcode.size(), &dst, sizeof(dst));
		std::fill(src + m_shellcode.size() + sizeof(dst), src + length, std::byte(0x90));

		VirtualProtect(src, length, old_prot, &old_prot);
		return true;
	}
}