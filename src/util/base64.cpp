#include "vpn/util/base64.hpp"
#include <sodium.h>

namespace vpn::util {

std::string base64_encode(std::span<const uint8_t> data) {
    // Calculate required buffer size
    size_t encoded_len = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string result(encoded_len, '\0');

    sodium_bin2base64(
        result.data(), encoded_len,
        data.data(), data.size(),
        sodium_base64_VARIANT_ORIGINAL
    );

    // Remove null terminator
    while (!result.empty() && result.back() == '\0') {
        result.pop_back();
    }

    return result;
}

std::optional<std::vector<uint8_t>> base64_decode(std::string_view encoded) {
    if (encoded.empty()) {
        return std::vector<uint8_t>{};
    }

    // Maximum decoded size
    size_t max_decoded_len = encoded.size() * 3 / 4 + 1;
    std::vector<uint8_t> result(max_decoded_len);
    size_t actual_len = 0;

    if (sodium_base642bin(
            result.data(), max_decoded_len,
            encoded.data(), encoded.size(),
            nullptr,  // ignore characters
            &actual_len,
            nullptr,  // end pointer
            sodium_base64_VARIANT_ORIGINAL
        ) != 0) {
        return std::nullopt;
    }

    result.resize(actual_len);
    return result;
}

} // namespace vpn::util
