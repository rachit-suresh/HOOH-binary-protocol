#include "frame.h"

namespace hooh {

void pack_header(const FrameHeader& h, uint8_t out[kHeaderSize]) {
    store_le24(out, h.length & 0x00FFFFFF);
    out[3] = static_cast<uint8_t>(((h.type & 0x0F) << 4) | (h.flags & 0x0F));
    store_le24(out + 4, h.stream_id & 0x00FFFFFF);
}

FrameHeader unpack_header(const uint8_t in[kHeaderSize]) {
    FrameHeader h;
    h.length = load_le24(in);
    h.type = static_cast<uint8_t>((in[3] >> 4) & 0x0F);
    h.flags = static_cast<uint8_t>(in[3] & 0x0F);
    h.stream_id = load_le24(in + 4);
    return h;
}

const char* frame_type_name(uint8_t type) {
    switch (type) {
        case TYPE_DATA: return "DATA";
        case TYPE_HEADERS: return "HEADERS";
        case TYPE_RST_STREAM: return "RST_STREAM";
        case TYPE_PING: return "PING";
        case TYPE_GOAWAY: return "GOAWAY";
        case TYPE_PONG: return "PONG";
        default: return "UNKNOWN";
    }
}

std::string flags_to_string(uint8_t flags) {
    std::string s;
    if (flags & FLAG_END_STREAM) {
        s += "ES";
    }
    if (flags & FLAG_END_HEADERS) {
        if (!s.empty()) s += "|";
        s += "EH";
    }
    return s.empty() ? "-" : s;
}

const char* error_code_name(uint8_t code) {
    switch (code) {
        case ERR_NO_ERROR: return "NO_ERROR";
        case ERR_PROTOCOL_ERROR: return "PROTOCOL_ERROR";
        case ERR_CANCELLED: return "CANCELLED";
        case ERR_INTERNAL: return "INTERNAL";
        default: return "UNKNOWN";
    }
}

} // namespace hooh
