#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <variant>
#include "frame.h"

namespace hooh {

enum StaticHeaderIndex : uint8_t {
    HDR_LITERAL = 0x00,
    HDR_METHOD = 0x01,
    HDR_PATH = 0x02,
    HDR_STATUS = 0x03,
    HDR_HOST = 0x04,
    HDR_USER_AGENT = 0x05,
    HDR_SERVER = 0x06,
    HDR_DATE = 0x07,
    HDR_CONTENT_TYPE = 0x08,
    HDR_CONTENT_LENGTH = 0x09,
    HDR_ACCEPT = 0x0A
};

inline constexpr uint8_t kStaticTableSize = 10;

const char* static_header_name(uint8_t index);
uint8_t static_header_index(const std::string& name);

struct HeaderField {
    std::string name;        // lowercase
    std::string value;
    uint8_t static_index{0}; // 1..10 if static, 0 if literal
};

enum class Direction {
    Request,
    Response
};

struct HeaderBlock {
    // Pseudo-headers
    std::string method;
    std::string path;
    std::string status;

    // Regular headers in order; duplicate headers: last wins
    std::vector<HeaderField> fields;

    // Content length parsed if present
    bool has_content_length{false};
    uint64_t content_length{0};

    // Helper functions
    bool has_header(const std::string& name) const;
    std::string get_header(const std::string& name) const;
    void set_header(const std::string& name, const std::string& value);
};

enum class BlockError {
    Ok = 0,
    MalformedGrammar,     // buffer overrun, zero-length name, invalid index 0x0B..0xFF
    UnknownPseudo,        // unknown pseudo header (begins with ':')
    MissingPseudo,        // missing required pseudo headers (:method, :path or :status)
    DuplicatePseudo,      // duplicate pseudo header
    WrongDirection,       // :status in request, or :method/:path in response
    PseudoAfterRegular,   // pseudo header found after regular headers
    InvalidMethod,        // invalid :method token
    InvalidPath,          // :path does not begin with '/' or has NUL
    InvalidStatus,        // :status not 3 ASCII digits
    InvalidContentLength  // content-length not valid ASCII digits fitting in 64 bits
};

const char* block_error_to_string(BlockError err);

// Decode raw bytes to HeaderBlock
std::variant<HeaderBlock, BlockError> decode_header_block(
    const uint8_t* data, size_t length, Direction dir);

// Encode HeaderBlock to raw bytes
std::vector<uint8_t> encode_header_block(const HeaderBlock& block, Direction dir);

} // namespace hooh
