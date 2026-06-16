#pragma once

#include <string>

namespace StringUtil {
    // Converts a UTF-8 encoded std::string to a UTF-16 std::wstring
    std::wstring utf8ToWide(const std::string& utf8Str);
}