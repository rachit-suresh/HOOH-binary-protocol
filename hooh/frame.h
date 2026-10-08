#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace hooh {

// Wire constants (§2, §3, §4)
inline constexpr size_t kHeaderSize = 7;
inline constexpr size_t kPrefaceSize = 10;
inline constexpr uint8_t kPreface[kPrefaceSize] = {
    0x48, 0x65, 0x4c, 0x6c, 0x4f, 0x4f, 0x6c, 0x4c, 0x65, 0x48 // "HeLlOOlLeH"
};

// Acceptance floor and default implementation limits (§4, §11)
inline constexpr uint32_t kAcceptFloor = 16384;      // 16 KiB
inline constexpr uint32_t kMaxGrammarLen = 16777215; // 2^24 - 1
inline constexpr uint32_t kMaxStreamId = 16777215;   // 2^24 - 1
inline constexpr uint32_t kDefaultImplLimit = 1048576; // 1 MiB

// Frame types (§5)
enum FrameType : uint8_t {
    TYPE_DATA = 0x0,
    TYPE_HEADERS = 0x1,
    TYPE_RST_STREAM = 0x2,
    TYPE_PING = 0x3,
    TYPE_GOAWAY = 0x4,
    TYPE_PONG = 0x5
};

// Flags (§6)
inline constexpr uint8_t FLAG_END_STREAM  = 0x01; // bit 0
inline constexpr uint8_t FLAG_END_HEADERS = 0x02; // bit 1

// Error codes (§11)
enum ErrorCode : uint8_t {
    ERR_NO_ERROR = 0,
    ERR_PROTOCOL_ERROR = 1,
    ERR_CANCELLED = 2,
    ERR_INTERNAL = 3
};

struct FrameHeader {
    uint32_t length{0};    // 24 bits
    uint8_t type{0};       // 4 bits
    uint8_t flags{0};      // 4 bits
    uint32_t stream_id{0}; // 24 bits
};

// Little-endian load/store helpers (§2, §4)
inline uint16_t load_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline void store_le16(uint8_t* p, uint16_t val) {
    p[0] = static_cast<uint8_t>(val & 0xFF);
    p[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
}

inline uint32_t load_le24(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16);
}

inline void store_le24(uint8_t* p, uint32_t val) {
    p[0] = static_cast<uint8_t>(val & 0xFF);
    p[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
}

inline uint64_t load_le64(const uint8_t* p) {
    uint64_t val = 0;
    for (size_t i = 0; i < 8; ++i) {
        val |= (static_cast<uint64_t>(p[i]) << (i * 8));
    }
    return val;
}

inline void store_le64(uint8_t* p, uint64_t val) {
    for (size_t i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
    }
}

// Header pack / unpack
void pack_header(const FrameHeader& h, uint8_t out[kHeaderSize]);
FrameHeader unpack_header(const uint8_t in[kHeaderSize]);

// Type and Flag name helpers for logging & hexdump
const char* frame_type_name(uint8_t type);
std::string flags_to_string(uint8_t flags);
const char* error_code_name(uint8_t code);

// Normalizes error code: unknown codes -> ERR_PROTOCOL_ERROR (§11)
inline ErrorCode normalize_error_code(uint8_t code) {
    if (code <= 3) {
        return static_cast<ErrorCode>(code);
    }
    return ERR_PROTOCOL_ERROR;
}

} // namespace hooh
