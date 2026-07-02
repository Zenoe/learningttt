#pragma once

#include <string>

namespace pipeclient {

bool sendShowInFolder(const std::wstring& path);
bool sendLog(const std::wstring& text);
bool setClipboardText(const std::wstring& boxName, const std::wstring& text);
bool clearClipboard(const std::wstring& boxName);
bool getClipboardText(const std::wstring& boxName, std::wstring& text,
                      bool& hasText);
bool hasClipboardText(const std::wstring& boxName, bool& hasText);

} // namespace pipeclient
