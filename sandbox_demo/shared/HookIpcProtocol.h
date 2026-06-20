#pragma once

#include <cstdint>

namespace hookipc {

inline constexpr wchar_t kPipeName[] =
    L"\\\\.\\pipe\\SandboxDemo_HookIpc_v1";
inline constexpr std::uint32_t kMagic = 0x5342484Bu; // 'SBHK'
inline constexpr std::uint32_t kVersion = 1u;
inline constexpr std::uint32_t kMaxText = 2048u;

enum class MessageType : std::uint32_t {
    ShowInFolder = 1,
    HookLog = 2,
};

struct Message {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t type;
    std::uint32_t textLength;
    std::uint32_t processId;
    std::uint32_t threadId;
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
           type == MessageType::HookLog;
}

} // namespace hookipc
