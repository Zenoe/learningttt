#pragma once

#include <cstdint>

namespace hookipc {

inline constexpr wchar_t kPipeName[] =
    L"\\\\.\\pipe\\SandboxDemo_HookIpc_v1";
inline constexpr std::uint32_t kMagic = 0x5342484Bu; // 'SBHK'
inline constexpr std::uint32_t kVersion = 1u;
inline constexpr std::uint32_t kMaxText = 2048u;
inline constexpr std::uint32_t kMaxBox = 64u;

enum class MessageType : std::uint32_t {
    ShowInFolder = 1,
    HookLog = 2,
    ClipboardSetText = 3,
    ClipboardClear = 4,
    ClipboardGetText = 5,
    ClipboardHasText = 6,
    ClipboardTextResponse = 7,
    ClipboardStatusResponse = 8,
};

struct Message {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t type;
    std::uint32_t textLength;
    std::uint32_t processId;
    std::uint32_t threadId;
    std::uint32_t result;
    wchar_t boxName[kMaxBox];
    wchar_t text[kMaxText];
};

inline bool isValid(const Message& message, std::uint32_t bytesRead)
{
    if (bytesRead != sizeof(Message) ||
        message.magic != kMagic ||
        message.version != kVersion ||
        message.textLength >= kMaxText) {
        return false;
    }

    const auto type = static_cast<MessageType>(message.type);
    return type == MessageType::ShowInFolder ||
           type == MessageType::HookLog ||
           type == MessageType::ClipboardSetText ||
           type == MessageType::ClipboardClear ||
           type == MessageType::ClipboardGetText ||
           type == MessageType::ClipboardHasText ||
           type == MessageType::ClipboardTextResponse ||
           type == MessageType::ClipboardStatusResponse;
}

} // namespace hookipc
