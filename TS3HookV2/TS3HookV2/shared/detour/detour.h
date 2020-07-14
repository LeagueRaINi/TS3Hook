#ifndef DETOUR_H
#define DETOUR_H

namespace shared::detour
{
	auto apply(std::byte* src, std::byte* dst, const std::size_t length) -> bool;
}

#endif // DETOUR_H