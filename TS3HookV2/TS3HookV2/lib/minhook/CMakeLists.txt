cmake_minimum_required(VERSION 3.8)

project(MinHook C)

add_library(MinHook STATIC
    "src/buffer.c"
    "src/hook.c"
    "src/trampoline.c"
    "src/hde/hde32.c"
    "src/hde/hde64.c"
)

target_include_directories(MinHook PUBLIC include)
