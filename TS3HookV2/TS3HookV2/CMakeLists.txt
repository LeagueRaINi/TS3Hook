cmake_minimum_required(VERSION 3.8)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory("lib/minhook")

add_library(TS3HookV2 SHARED "entry.cpp"
	"shared/shared.h"
	"shared/console/console.cpp"
	"shared/pattern_scanner/pattern_scanner.cpp"
)

target_link_libraries(TS3HookV2 PRIVATE MinHook)