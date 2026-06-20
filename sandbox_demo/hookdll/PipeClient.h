#pragma once

#include <string>

namespace pipeclient {

bool sendShowInFolder(const std::wstring& path);
bool sendLog(const std::wstring& text);

} // namespace pipeclient
