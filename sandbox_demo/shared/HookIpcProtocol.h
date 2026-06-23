#pragma once

#include <cstdint>

namespace hookipc {

inline constexpr wchar_t kPipeName[] =
    L"\\\\.\\pipe\\SandboxDemo_HookIpc_v1";
inline constexpr std::uint32_t kMagic = 0x5342484Bu; // 'SBHK'
inline constexpr std::uint32_t kVersion = 1u;
inline constexpr std::uint32_t kMaxText = 8192u;
inline constexpr std::uint32_t kMaxBox = 64u;

enum class MessageType : std::uint32_t {
    ShowInFolder = 1,
    HookLog = 2,
    ClipboardSetText = 3,
    ClipboardGetText = 4,
    ClipboardHasText = 5,
    ClipboardTextResponse = 6,
    ClipboardStatusResponse = 7,
};

struct Message {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t type;
    std::uint32_t textLength;
    std::uint32_t processId;
    std::uint32_t threadId;
    wchar_t boxName[kMaxBox];
    wchar_t text[kMaxText];
};

inline bool isKnownType(MessageType type)
{
    return type == MessageType::ShowInFolder ||
           type == MessageType::HookLog ||
           type == MessageType::ClipboardSetText ||
           type == MessageType::ClipboardGetText ||
           type == MessageType::ClipboardHasText ||
           type == MessageType::ClipboardTextResponse ||
           type == MessageType::ClipboardStatusResponse;
}

inline bool isValid(const Message& message, std::uint32_t bytesRead)
{
    if (bytesRead != sizeof(Message) ||
        message.magic != kMagic ||
        message.version != kVersion ||
        message.textLength >= kMaxText) {
        return false;
    }

    return isKnownType(static_cast<MessageType>(message.type));
}

} // namespace hookipc
