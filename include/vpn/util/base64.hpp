#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <span>
#include <cstdint>

namespace vpn::util {

// Base64 encoding/decoding utilities

// Encode binary data to base64 string
std::string base64_encode(std::span<const uint8_t> data);

// Decode base64 string to binary data
// Returns nullopt if the input is not valid base64
std::optional<std::vector<uint8_t>> base64_decode(std::string_view encoded);

// WireGuard uses standard base64 (not URL-safe) with padding

} // namespace vpn::util
