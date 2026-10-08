#include "hexdump.h"
#include <sstream>
#include <iomanip>
#include <cctype>

namespace hooh {

static std::string to_hex_byte(uint8_t b) {
    std::ostringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return ss.str();
}

std::string format_preface_log(bool sent, size_t offset, const uint8_t preface[kPrefaceSize]) {
    std::ostringstream ss;
    ss << (sent ? "-> " : "<- ");
    ss << "[" << std::setw(6) << std::setfill('0') << offset << "] ";
    for (size_t i = 0; i < kPrefaceSize; ++i) {
        ss << to_hex_byte(preface[i]) << " ";
    }
    ss << " preface \"";
    for (size_t i = 0; i < kPrefaceSize; ++i) {
        ss << static_cast<char>(preface[i]);
    }
    ss << "\"\n";
    return ss.str();
}

std::string format_hex_ascii(const uint8_t* data, size_t length, size_t indent) {
    std::ostringstream ss;
    std::string ind(indent, ' ');
    size_t i = 0;
    while (i < length) {
        ss << ind;
        size_t line_len = std::min(length - i, size_t{16});
        for (size_t j = 0; j < 16; ++j) {
            if (j < line_len) {
                ss << to_hex_byte(data[i + j]) << " ";
            } else {
                ss << "   ";
            }
        }
        ss << " |";
        for (size_t j = 0; j < line_len; ++j) {
            char c = static_cast<char>(data[i + j]);
            ss << (std::isprint(static_cast<unsigned char>(c)) ? c : '.');
        }
        ss << "|\n";
        i += line_len;
    }
    return ss.str();
}

std::string format_frame_log(
    bool sent,
    size_t offset,
    const FrameHeader& hdr,
    const uint8_t* payload,
    Direction dir) {

    std::ostringstream ss;
    ss << (sent ? "-> " : "<- ");
    ss << "[" << std::setw(6) << std::setfill('0') << offset << "] ";
    ss << "len=" << hdr.length << " B "
       << "type=" << frame_type_name(hdr.type) << " "
       << "flags=" << flags_to_string(hdr.flags) << " "
       << "stream=" << hdr.stream_id << "\n";

    if (hdr.length == 0) {
        return ss.str();
    }

    if (hdr.type == TYPE_HEADERS && payload) {
        auto dec = decode_header_block(payload, hdr.length, dir);
        if (std::holds_alternative<HeaderBlock>(dec)) {
            const auto& blk = std::get<HeaderBlock>(dec);
            if (dir == Direction::Request) {
                ss << "     :method = \"" << blk.method << "\"\n";
                ss << "     :path = \"" << blk.path << "\"\n";
            } else {
                ss << "     :status = \"" << blk.status << "\"\n";
            }
            for (const auto& f : blk.fields) {
                if (f.static_index != 0) {
                    ss << "     " << f.name << " = \"" << f.value << "\"\n";
                } else {
                    ss << "     literal \"" << f.name << "\" = \"" << f.value << "\"\n";
                }
            }
        } else {
            ss << "     [Malformed Header Block: "
               << block_error_to_string(std::get<BlockError>(dec)) << "]\n";
            ss << format_hex_ascii(payload, hdr.length, 5);
        }
    } else if (hdr.type == TYPE_DATA && payload) {
        ss << format_hex_ascii(payload, hdr.length, 5);
    } else if (hdr.type == TYPE_RST_STREAM && payload && hdr.length == 1) {
        ss << "     error = " << static_cast<int>(payload[0])
           << " (" << error_code_name(payload[0]) << ")\n";
    } else if ((hdr.type == TYPE_PING || hdr.type == TYPE_PONG) && payload && hdr.length == 8) {
        ss << "     challenge = ";
        for (size_t i = 0; i < 8; ++i) {
            ss << to_hex_byte(payload[i]) << " ";
        }
        ss << "\n";
    } else if (hdr.type == TYPE_GOAWAY && payload && hdr.length == 4) {
        uint32_t last_id = load_le24(payload);
        uint8_t err = payload[3];
        ss << "     last_stream_id = " << last_id
           << " error = " << static_cast<int>(err)
           << " (" << error_code_name(err) << ")\n";
    } else if (payload) {
        ss << format_hex_ascii(payload, hdr.length, 5);
    }

    return ss.str();
}

} // namespace hooh
