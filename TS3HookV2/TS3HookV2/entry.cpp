#include "shared/shared.h"

#include <MinHook.h>
#include <algorithm>
#include <iostream>
#include <regex>
#include <thread>

static void* packet_detour_ret = nullptr;

const auto client_version_regex = std::regex(R"(client_version=([^\s]+)\\s\[Build:\\s([0-9]+)\])");
const auto client_version_sign_regex = std::regex(R"(client_version_sign=([^ ]+))");
const auto client_platform_regex = std::regex(R"(client_platform=([A-z.]+))");
const auto client_nickname_regex = std::regex(R"(client_nickname=([^\s]+))");

constexpr std::string_view blocked_cmds[] =
{
    "setconnectioninfo",
    "connectioninfoautoupdate",
    "clientchatcomposing"
};

struct Packet
{
    void* VTable;
    char* Data;
    std::uint32_t Size;
};

static auto process_packet(Packet* packet) -> void
{
    auto str = std::string(packet->Data + 13, packet->Size - 13);
    if (!str.starts_with("clientinit "))
    {
        for (const auto& filter : blocked_cmds)
        {
            if (str.compare(0, filter.size(), filter))
                continue;

            std::fill(packet->Data + 13, packet->Data + packet->Size, ' ');
            return;
        }
    }
    else
    {
        std::smatch version_match, platform_match, version_sign_match;

        if (std::regex_search(str,      version_match,      client_version_regex) &&
            std::regex_search(str,     platform_match,     client_platform_regex) &&
            std::regex_search(str, version_sign_match, client_version_sign_regex))
        {
            str.replace(version_sign_match[1].first, version_sign_match[1].second, "+Y1iB58sLO38/4AI1YRUlEhXhhrbkAVbaSmOcZj0IrTmQm1eY+prEYJPQgF8StFdjWmAGmMG3ezzb0wEzRE3CQ==");
            str.replace(    platform_match[1].first,     platform_match[1].second, "macOS");
            str.replace(     version_match[2].first,      version_match[2].second, "1588064367");
            str.replace(     version_match[1].first,      version_match[1].second, "5.0.0-beta.25");

            if (str.length() > packet->Size - 13)
            {
                auto heap = GetProcessHeap();
                auto buff = reinterpret_cast<char*>(HeapAlloc(heap, 0, str.length() + 13));

                std::memcpy(buff, packet->Data, 13);
                std::memcpy(buff + 13, str.c_str(), str.length());

                HeapFree(heap, 0, packet->Data);

                packet->Data = buff;
            }
            else
            {
                std::memcpy(packet->Data + 13, str.c_str(), str.length());
            }

            packet->Size = std::uint32_t(str.length() + 13);
        }
    }

#ifdef _DEBUG
    std::cout << str << std::endl;
#endif
}

[[gnu::naked]] static auto packet_detour() -> void
{
    __asm
    {
        push rax
        push rcx

        mov  rcx, rdi
        call process_packet

        pop  rcx
        pop  rax

        jmp  packet_detour_ret
    }
}

[[gnu::constructor]] static auto Init() -> void
{
    shared::console::attach();

    std::thread init_thread([] {
        MH_Initialize();

        shared::console::attach();

        std::cout << "searching pattern..." << std::endl;

        const auto packet_off = shared::pattern_scanner::scan("ts3client_win64.exe",
            "\x80\x7C\x24\x00\x00\x75\x1A", "xxx??xx", -13);

        if (!packet_off)
        {
            std::cout << "  - failed!" << std::endl;
            return;
        }

        std::cout << "  - " << std::hex << packet_off << "\nhooking..." << std::endl;

        if (MH_CreateHook(reinterpret_cast<void*>(packet_off), reinterpret_cast<void*>(&packet_detour),
            &packet_detour_ret) != MH_OK)
        {
            std::cout << "  - failed to create hook" << std::endl;
            return;
        }

        if (MH_EnableHook(reinterpret_cast<void*>(packet_off)) != MH_OK)
        {
            std::cout << "  - failed to enable hook" << std::endl;
            return;
        }

        std::cout << "  - hooked!" << std::endl;
    });

    init_thread.detach();
}

[[gnu::destructor]] static auto Deinit() -> void
{
    std::cout << "unloading..." << std::endl;

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    shared::console::detach();
}