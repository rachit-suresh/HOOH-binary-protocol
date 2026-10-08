#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_set>
#include <chrono>
#include <functional>
#include "frame.h"
#include "headerblock.h"
#include "net_compat.h"

namespace hooh {

enum class Role {
    Server,
    Client
};

enum class FrameActionType {
    Process,
    Skip,
    Ignore,
    StreamError,
    ConnectionError
};

struct FrameAction {
    FrameActionType type;
    int status_or_code{0}; // status code (400, 413) or protocol error code
    std::string detail;
};

struct StreamState {
    uint32_t id{0};
    bool headers_seen_in{false};
    bool headers_seen_out{false};
    bool end_stream_in{false};
    bool end_stream_out{false};
    bool aborted{false};

    // Buffered request payload
    std::vector<uint8_t> headers_payload;
    uint8_t headers_flags{0};
    uint64_t body_bytes_seen{0};
};

class Session {
public:
    Session(Role role, socket_t sock, bool verbose = false, uint32_t impl_limit = kDefaultImplLimit);
    ~Session() = default;

    Role role() const { return role_; }
    socket_t socket() const { return sock_; }

    // Preface exchange (§3)
    bool do_preface_exchange();

    // Sends a raw frame
    bool send_frame(const FrameHeader& hdr, const uint8_t* payload, size_t payload_len);

    // Sends GOAWAY frame (§8.6)
    bool send_goaway(uint32_t last_stream_id, ErrorCode error);

    // Sends RST_STREAM frame (§8.3)
    bool send_rst_stream(uint32_t stream_id, ErrorCode error);

    // Reads exact N bytes with timeout
    bool read_exact(uint8_t* dst, size_t count, int timeout_ms);

    // Reads and skips N bytes in bounded chunks (Step 2 & Step 4)
    bool skip_bytes(size_t count, int timeout_ms);

    // Reads 7-byte header and classifies according to §11 steps 1..6
    bool read_and_classify_frame(
        FrameHeader* out_hdr,
        std::vector<uint8_t>* out_payload,
        FrameAction* out_action,
        int timeout_ms);

    // State queries and mutations
    bool is_stream_open(uint32_t id) const;
    void open_client_stream(uint32_t id);
    void close_stream(uint32_t id);
    void abort_stream(uint32_t id);

    void set_last_committed_stream(uint32_t id) { last_committed_stream_id_ = id; }
    uint32_t last_committed_stream() const { return last_committed_stream_id_; }

    uint32_t highest_used_id() const { return highest_used_id_; }
    void mark_id_used(uint32_t id);

    void record_traffic() { last_traffic_time_ = std::chrono::steady_clock::now(); }
    int seconds_since_last_traffic() const;

    void set_outstanding_ping(uint64_t challenge) {
        outstanding_ping_ = challenge;
        has_outstanding_ping_ = true;
    }
    bool has_outstanding_ping() const { return has_outstanding_ping_; }
    uint64_t outstanding_ping() const { return outstanding_ping_; }
    void clear_outstanding_ping() { has_outstanding_ping_ = false; }

    StreamState* current_stream() { return open_stream_id_ ? &current_stream_state_ : nullptr; }

private:
    Role role_;
    socket_t sock_;
    bool verbose_;
    uint32_t impl_limit_;

    size_t wire_offset_sent_{0};
    size_t wire_offset_recv_{0};

    uint32_t highest_used_id_{0};
    uint32_t open_stream_id_{0};
    StreamState current_stream_state_;

    std::unordered_set<uint32_t> used_stream_ids_;
    std::unordered_set<uint32_t> aborted_by_client_ids_;
    uint32_t last_committed_stream_id_{0};

    bool has_outstanding_ping_{false};
    uint64_t outstanding_ping_{0};

    std::chrono::steady_clock::time_point last_traffic_time_;

    FrameAction classify_frame(const FrameHeader& hdr);
};

} // namespace hooh
