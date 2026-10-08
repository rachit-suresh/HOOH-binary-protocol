#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include "frame.h"
#include "headerblock.h"

namespace hooh {

// Formats a preface exchange line
std::string format_preface_log(bool sent, size_t offset, const uint8_t preface[kPrefaceSize]);

// Formats a frame log entry for -v
// sent: true if outgoing (->), false if incoming (<-)
// offset: byte offset on the connection
std::string format_frame_log(
    bool sent,
    size_t offset,
    const FrameHeader& hdr,
    const uint8_t* payload,
    Direction dir);

// Format hex bytes with printable ASCII
std::string format_hex_ascii(const uint8_t* data, size_t length, size_t indent = 2);

} // namespace hooh
