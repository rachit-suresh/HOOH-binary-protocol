#pragma once

#include <string>
#include <cstdint>
#include <functional>
#include "frame.h"
#include "headerblock.h"
#include "pathutil.h"

namespace hooh {

// Callback type to send a frame onto the connection
// (header, payload_ptr, payload_len)
using FrameSender = std::function<bool(const FrameHeader&, const uint8_t*, size_t)>;

// Sends an error response on stream_id (§10)
// Error responses (400, 404, 405, 413, 501) MUST consist of exactly one HEADERS frame
// containing only :status, flags END_HEADERS|END_STREAM, and no body.
bool send_error_response(FrameSender sender, uint32_t stream_id, int status_code);

// Serves a file on stream_id (§10)
// Returns true on success, false on transport error.
// If file read fails or shrinks during streaming, sends RST_STREAM(INTERNAL).
bool serve_file_response(
    FrameSender sender,
    uint32_t stream_id,
    const ResolvedFile& file);

} // namespace hooh
