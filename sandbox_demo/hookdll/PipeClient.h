#pragma once

#include <string>

namespace pipeclient {

bool sendShowInFolder(const std::wstring& path);
bool sendLog(const std::wstring& text);
bool setClipboardText(const std::wstring& text);
bool getClipboardText(std::wstring& text);
bool hasClipboardText();

} // namespace pipeclient
