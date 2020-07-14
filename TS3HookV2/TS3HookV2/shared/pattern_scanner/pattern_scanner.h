#ifndef PATTERN_SCANNER_H
#define PATTERN_SCANNER_H

namespace shared::pattern_scanner
{
	auto scan(std::string_view module_name, std::string_view pattern, std::string_view mask, std::int32_t offset = 0) -> std::uintptr_t;
}

#endif // PATTERN_SCANNER_H