#include "StringUtil.h"
#include <windows.h>
#include <stdexcept>

namespace StringUtil {

    std::wstring utf8ToWide(const std::string& utf8Str) {
        if (utf8Str.empty()) {
            return std::wstring();
        }

        // 1. Calculate the required buffer size
        int sizeNeeded = MultiByteToWideChar(
            CP_UTF8,
            0,
            utf8Str.c_str(),
            static_cast<int>(utf8Str.length()),
            nullptr,
            0
        );

        if (sizeNeeded <= 0) {
            throw std::runtime_error("Failed to convert UTF-8 string to wide string (size calculation).");
        }

        // 2. Allocate buffer and convert
        std::wstring wideStr(sizeNeeded, L'\0');

        int result = MultiByteToWideChar(
            CP_UTF8,
            0,
            utf8Str.c_str(),
            static_cast<int>(utf8Str.length()),
            &wideStr[0],
            sizeNeeded
        );

        if (result <= 0) {
            throw std::runtime_error("Failed to convert UTF-8 string to wide string (conversion).");
        }

        return wideStr;
    }

} // namespace StringUtil