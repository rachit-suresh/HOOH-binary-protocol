#include "session.h"
#include "hexdump.h"
#include <iostream>
#include <algorithm>
#include <cstring>

namespace hooh {

Session::Session(Role role, socket_t sock, bool verbose, uint32_t impl_limit)
    : role_(role), sock_(sock), verbose_(verbose), impl_limit_(std::max(kAcceptFloor, impl_limit)) {
    last_traffic_time_ = std::chrono::steady_clock::now();
}

int Session::seconds_since_last_traffic() const {
    auto now = std::chrono::steady_clock::now();
    return static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(now - last_traffic_time_).count());
}

bool Session::read_exact(uint8_t* dst, size_t count, int timeout_ms) {
    size_t total = 0;
    while (total < count) {
        pollfd pfd;
        pfd.fd = sock_;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int pr = poll_sockets(&pfd, 1, timeout_ms);
        if (pr <= 0) {
            return false; // timeout or error
        }

        int n = recv(sock_, reinterpret_cast<char*>(dst + total), static_cast<int>(count - total), 0);
        if (n <= 0) {
            return false; // EOF or socket error
        }

        total += n;
        record_traffic();
    }
    wire_offset_recv_ += total;
    return true;
}

bool Session::skip_bytes(size_t count, int timeout_ms) {
    uint8_t scratch[4096];
    size_t remaining = count;
    while (remaining > 0) {
        size_t to_read = std::min(remaining, sizeof(scratch));
        if (!read_exact(scratch, to_read, timeout_ms)) {
            return false;
        }
        remaining -= to_read;
    }
    return true;
}

bool Session::send_frame(const FrameHeader& hdr, const uint8_t* payload, size_t payload_len) {
    uint8_t hdr_bytes[kHeaderSize];
    pack_header(hdr, hdr_bytes);

    if (verbose_) {
        Direction dir = (role_ == Role::Client) ? Direction::Request : Direction::Response;
        std::cerr << format_frame_log(true, wire_offset_sent_, hdr, payload, dir);
    }

    // Send 7-byte header
    size_t total = 0;
    while (total < kHeaderSize) {
        int n = send(sock_, reinterpret_cast<const char*>(hdr_bytes + total),
                     static_cast<int>(kHeaderSize - total), 0);
        if (n <= 0) return false;
        total += n;
    }
    wire_offset_sent_ += kHeaderSize;

    // Send payload if any
    if (payload && payload_len > 0) {
        total = 0;
        while (total < payload_len) {
            int n = send(sock_, reinterpret_cast<const char*>(payload + total),
                         static_cast<int>(payload_len - total), 0);
            if (n <= 0) return false;
            total += n;
        }
        wire_offset_sent_ += payload_len;
    }

    if (role_ == Role::Client && hdr.type == TYPE_HEADERS) {
        open_client_stream(hdr.stream_id);
    } else if (role_ == Role::Server && hdr.type == TYPE_HEADERS) {
        if (open_stream_id_ == hdr.stream_id) {
            current_stream_state_.headers_seen_out = true;
        }
    }
    if (hdr.flags & FLAG_END_STREAM) {
        if (open_stream_id_ == hdr.stream_id) {
            current_stream_state_.end_stream_out = true;
        }
    }

    record_traffic();
    return true;
}

void Session::open_client_stream(uint32_t id) {
    open_stream_id_ = id;
    current_stream_state_ = StreamState{};
    current_stream_state_.id = id;
    current_stream_state_.headers_seen_out = true;
    mark_id_used(id);
}

bool Session::send_goaway(uint32_t last_stream_id, ErrorCode error) {
    uint8_t p[4];
    store_le24(p, last_stream_id & 0x00FFFFFF);
    p[3] = static_cast<uint8_t>(error);

    FrameHeader h;
    h.length = 4;
    h.type = TYPE_GOAWAY;
    h.flags = 0;
    h.stream_id = 0;

    return send_frame(h, p, 4);
}

bool Session::send_rst_stream(uint32_t stream_id, ErrorCode error) {
    uint8_t p[1];
    p[0] = static_cast<uint8_t>(error);

    FrameHeader h;
    h.length = 1;
    h.type = TYPE_RST_STREAM;
    h.flags = 0;
    h.stream_id = stream_id;

    if (role_ == Role::Client) {
        aborted_by_client_ids_.insert(stream_id);
    }
    abort_stream(stream_id);

    return send_frame(h, p, 1);
}

bool Session::do_preface_exchange() {
    if (role_ == Role::Client) {
        // Client sends preface first
        if (verbose_) {
            std::cerr << format_preface_log(true, wire_offset_sent_, kPreface);
        }
        int n = send(sock_, reinterpret_cast<const char*>(kPreface), static_cast<int>(kPrefaceSize), 0);
        if (n != static_cast<int>(kPrefaceSize)) return false;
        wire_offset_sent_ += kPrefaceSize;
        record_traffic();

        // Read server's preface
        uint8_t reply[kPrefaceSize];
        if (!read_exact(reply, kPrefaceSize, 60000)) {
            return false;
        }
        if (std::memcmp(reply, kPreface, kPrefaceSize) != 0) {
            return false;
        }
        if (verbose_) {
            std::cerr << format_preface_log(false, wire_offset_recv_ - kPrefaceSize, reply);
        }
        return true;
    } else {
        // Server reads client's preface first
        uint8_t client_preface[kPrefaceSize];
        for (size_t i = 0; i < kPrefaceSize; ++i) {
            pollfd pfd;
            pfd.fd = sock_;
            pfd.events = POLLIN;
            pfd.revents = 0;
            if (poll_sockets(&pfd, 1, 60000) <= 0) return false;
            int n = recv(sock_, reinterpret_cast<char*>(&client_preface[i]), 1, 0);
            if (n != 1) return false;
            record_traffic();
            wire_offset_recv_ += 1;
            if (client_preface[i] != kPreface[i]) {
                // Mismatch: MUST close immediately without transmitting anything (§3)
                return false;
            }
        }
        if (verbose_) {
            std::cerr << format_preface_log(false, wire_offset_recv_ - kPrefaceSize, client_preface);
        }

        // Echo preface back
        if (verbose_) {
            std::cerr << format_preface_log(true, wire_offset_sent_, kPreface);
        }
        int n = send(sock_, reinterpret_cast<const char*>(kPreface), static_cast<int>(kPrefaceSize), 0);
        if (n != static_cast<int>(kPrefaceSize)) return false;
        wire_offset_sent_ += kPrefaceSize;
        record_traffic();
        return true;
    }
}

bool Session::is_stream_open(uint32_t id) const {
    return (open_stream_id_ == id && id != 0);
}

void Session::mark_id_used(uint32_t id) {
    if (id > highest_used_id_) {
        highest_used_id_ = id;
    }
    used_stream_ids_.insert(id);
}

void Session::close_stream(uint32_t id) {
    if (open_stream_id_ == id) {
        open_stream_id_ = 0;
        current_stream_state_ = StreamState{};
    }
    mark_id_used(id);
}

void Session::abort_stream(uint32_t id) {
    if (open_stream_id_ == id) {
        current_stream_state_.aborted = true;
        close_stream(id);
    } else {
        mark_id_used(id);
    }
}

FrameAction Session::classify_frame(const FrameHeader& hdr) {
    // Step 2: Type undefined or optional not implemented (§11 Step 2)
    if (hdr.type >= 0x6) {
        return {FrameActionType::Skip, 0, "Unknown frame type"};
    }

    // Step 3: Ownership and IDs (§11 Step 3)
    if (hdr.type == TYPE_PING || hdr.type == TYPE_PONG || hdr.type == TYPE_GOAWAY) {
        if (hdr.stream_id != 0) {
            return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "Control frame on non-zero stream"};
        }
    } else if (hdr.type == TYPE_HEADERS || hdr.type == TYPE_DATA) {
        if (hdr.stream_id == 0) {
            return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "HEADERS/DATA on stream 0"};
        }
    } else if (hdr.type == TYPE_RST_STREAM) {
        if (hdr.stream_id == 0) {
            return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "RST_STREAM on stream 0"};
        }
    }

    if (hdr.stream_id != 0 && (hdr.stream_id % 2 == 0)) {
        return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "Non-zero even stream ID"};
    }

    uint32_t s = hdr.stream_id;

    if (role_ == Role::Client) {
        // Abort-ignore rule checked before new, gap, and closed
        if (aborted_by_client_ids_.count(s)) {
            return {FrameActionType::Ignore, 0, "Client aborted ID"};
        }

        if (hdr.type == TYPE_HEADERS) {
            if (s != open_stream_id_) {
                return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "HEADERS on stream client did not open"};
            }
            if (current_stream_state_.headers_seen_in) {
                return {FrameActionType::StreamError, ERR_PROTOCOL_ERROR, "Duplicate response HEADERS"};
            }
        } else if (hdr.type == TYPE_DATA || hdr.type == TYPE_RST_STREAM) {
            if (s > highest_used_id_ || (s <= highest_used_id_ && s != open_stream_id_ && !used_stream_ids_.count(s))) {
                return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "DATA/RST on new or gap ID"};
            }
            if (used_stream_ids_.count(s) && s != open_stream_id_) {
                return {FrameActionType::Ignore, 0, "DATA/RST on closed ID"};
            }
        }
    } else { // Role::Server
        if (hdr.type == TYPE_HEADERS) {
            bool is_new = (s > highest_used_id_);
            bool is_gap = (s < highest_used_id_ && !used_stream_ids_.count(s));
            bool is_closed = (used_stream_ids_.count(s) && s != open_stream_id_);

            if (is_gap || is_closed) {
                return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "HEADERS on gap or closed ID"};
            }
            if (is_new) {
                mark_id_used(s);
                if (open_stream_id_ != 0) {
                    // One-stream limit exceeded: stream error on the new stream
                    return {FrameActionType::StreamError, 400, "One-stream limit exceeded"};
                }
                open_stream_id_ = s;
                current_stream_state_ = StreamState{};
                current_stream_state_.id = s;
                current_stream_state_.headers_seen_in = true;
            } else if (s == open_stream_id_) {
                if (current_stream_state_.headers_seen_in) {
                    return {FrameActionType::StreamError, 400, "Duplicate request HEADERS"};
                }
            }
        } else if (hdr.type == TYPE_DATA || hdr.type == TYPE_RST_STREAM) {
            bool is_new = (s > highest_used_id_);
            bool is_gap = (s < highest_used_id_ && !used_stream_ids_.count(s));
            bool is_closed = (used_stream_ids_.count(s) && s != open_stream_id_);

            if (is_new || is_gap) {
                return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "DATA/RST on new or gap ID"};
            }
            if (is_closed) {
                return {FrameActionType::Ignore, 0, "DATA/RST on closed ID"};
            }
        }
    }

    // Step 4: Size (§11 Step 4)
    if (hdr.length > impl_limit_) {
        if (hdr.stream_id == 0) {
            return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "Oversize frame on stream 0"};
        } else {
            return {FrameActionType::StreamError, 413, "Frame length exceeds implementation limit"};
        }
    }

    // Step 5: Shape (§11 Step 5)
    bool shape_error = false;
    if (hdr.type == TYPE_RST_STREAM && hdr.length != 1) shape_error = true;
    if ((hdr.type == TYPE_PING || hdr.type == TYPE_PONG) && hdr.length != 8) shape_error = true;
    if (hdr.type == TYPE_GOAWAY && hdr.length != 4) shape_error = true;
    if (hdr.type == TYPE_DATA && hdr.length == 0) shape_error = true;

    // Defined flags check (bits 0 and 1)
    if (hdr.type == TYPE_DATA) {
        if (hdr.flags & FLAG_END_HEADERS) shape_error = true;
    } else if (hdr.type == TYPE_HEADERS) {
        if ((hdr.flags & FLAG_END_HEADERS) == 0) shape_error = true; // END_HEADERS MUST be 1
    } else if (hdr.type == TYPE_RST_STREAM || hdr.type == TYPE_PING ||
               hdr.type == TYPE_GOAWAY || hdr.type == TYPE_PONG) {
        if ((hdr.flags & (FLAG_END_STREAM | FLAG_END_HEADERS)) != 0) shape_error = true;
    }

    if (shape_error) {
        if (hdr.stream_id == 0) {
            return {FrameActionType::ConnectionError, ERR_PROTOCOL_ERROR, "Malformed frame shape on stream 0"};
        } else {
            return {FrameActionType::StreamError, 400, "Malformed frame shape on stream"};
        }
    }

    return {FrameActionType::Process, 0, ""};
}

bool Session::read_and_classify_frame(
    FrameHeader* out_hdr,
    std::vector<uint8_t>* out_payload,
    FrameAction* out_action,
    int timeout_ms) {

    uint8_t hdr_bytes[kHeaderSize];
    if (!read_exact(hdr_bytes, kHeaderSize, timeout_ms)) {
        return false; // EOF or timeout
    }

    FrameHeader hdr = unpack_header(hdr_bytes);
    if (out_hdr) *out_hdr = hdr;

    FrameAction action = classify_frame(hdr);
    if (out_action) *out_action = action;

    if (action.type == FrameActionType::Skip || action.type == FrameActionType::Ignore) {
        if (hdr.length > 0) {
            if (!skip_bytes(hdr.length, timeout_ms)) return false;
        }
        if (verbose_) {
            Direction dir = (role_ == Role::Client) ? Direction::Response : Direction::Request;
            std::cerr << format_frame_log(false, wire_offset_recv_ - kHeaderSize - hdr.length, hdr, nullptr, dir);
        }
        return true;
    }

    if (action.type == FrameActionType::StreamError) {
        if (hdr.length > 0) {
            if (!skip_bytes(hdr.length, timeout_ms)) return false;
        }
        if (verbose_) {
            Direction dir = (role_ == Role::Client) ? Direction::Response : Direction::Request;
            std::cerr << format_frame_log(false, wire_offset_recv_ - kHeaderSize - hdr.length, hdr, nullptr, dir);
        }
        return true;
    }

    if (action.type == FrameActionType::ConnectionError) {
        return true; // Return so caller can send GOAWAY and close
    }

    // Process
    if (out_payload) {
        out_payload->resize(hdr.length);
        if (hdr.length > 0) {
            if (!read_exact(out_payload->data(), hdr.length, timeout_ms)) {
                return false;
            }
        }
        if (verbose_) {
            Direction dir = (role_ == Role::Client) ? Direction::Response : Direction::Request;
            std::cerr << format_frame_log(false, wire_offset_recv_ - kHeaderSize - hdr.length, hdr, out_payload->data(), dir);
        }
    }

    return true;
}

} // namespace hooh
