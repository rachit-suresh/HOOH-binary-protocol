#include "fileserve.h"
#include <fstream>
#include <vector>
#include <iostream>

namespace hooh {

bool send_error_response(FrameSender sender, uint32_t stream_id, int status_code) {
    HeaderBlock blk;
    blk.status = std::to_string(status_code);

    std::vector<uint8_t> payload = encode_header_block(blk, Direction::Response);

    FrameHeader h;
    h.length = static_cast<uint32_t>(payload.size());
    h.type = TYPE_HEADERS;
    h.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
    h.stream_id = stream_id;

    return sender(h, payload.data(), payload.size());
}

bool serve_file_response(
    FrameSender sender,
    uint32_t stream_id,
    const ResolvedFile& file) {

    std::ifstream ifs(file.canonical_path, std::ios::binary);
    if (!ifs.is_open()) {
        // Read failure before response starts is hidden as 404 (§10)
        return send_error_response(sender, stream_id, 404);
    }

    HeaderBlock blk;
    blk.status = "200";
    if (!file.mime_type.empty()) {
        blk.set_header("content-type", file.mime_type);
    }

    if (file.size == 0) {
        // Empty body: HEADERS carrying END_HEADERS|END_STREAM with no DATA frames (§8.2)
        std::vector<uint8_t> payload = encode_header_block(blk, Direction::Response);
        FrameHeader h;
        h.length = static_cast<uint32_t>(payload.size());
        h.type = TYPE_HEADERS;
        h.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
        h.stream_id = stream_id;
        return sender(h, payload.data(), payload.size());
    }

    // Send HEADERS with END_HEADERS only
    std::vector<uint8_t> payload = encode_header_block(blk, Direction::Response);
    FrameHeader h;
    h.length = static_cast<uint32_t>(payload.size());
    h.type = TYPE_HEADERS;
    h.flags = FLAG_END_HEADERS;
    h.stream_id = stream_id;

    if (!sender(h, payload.data(), payload.size())) {
        return false;
    }

    // Stream body in DATA frames (chunk <= kAcceptFloor)
    uint64_t remaining = file.size;
    std::vector<char> buffer(kAcceptFloor);

    while (remaining > 0) {
        size_t chunk_size = static_cast<size_t>(std::min<uint64_t>(remaining, kAcceptFloor));
        ifs.read(buffer.data(), static_cast<std::streamsize>(chunk_size));
        std::streamsize bytes_read = ifs.gcount();

        if (bytes_read <= 0 || static_cast<size_t>(bytes_read) != chunk_size) {
            // File shrank or read error occurred during transmission (§10):
            // "a file that shrinks or errors during a read after the 200 response has started
            // cannot be un-sent, so it aborts the stream with RST_STREAM(INTERNAL)."
            std::cerr << "File read error or shrink on stream " << stream_id << "\n";
            FrameHeader rst;
            rst.length = 1;
            rst.type = TYPE_RST_STREAM;
            rst.flags = 0;
            rst.stream_id = stream_id;
            uint8_t err_code = ERR_INTERNAL;
            sender(rst, &err_code, 1);
            return false;
        }

        remaining -= chunk_size;

        FrameHeader data_hdr;
        data_hdr.length = static_cast<uint32_t>(chunk_size);
        data_hdr.type = TYPE_DATA;
        data_hdr.flags = (remaining == 0) ? FLAG_END_STREAM : 0;
        data_hdr.stream_id = stream_id;

        if (!sender(data_hdr, reinterpret_cast<const uint8_t*>(buffer.data()), chunk_size)) {
            return false;
        }
    }

    return true;
}

} // namespace hooh
