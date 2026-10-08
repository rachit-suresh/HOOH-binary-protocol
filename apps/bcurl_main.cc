#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include "hooh/frame.h"
#include "hooh/headerblock.h"
#include "hooh/session.h"
#include "hooh/net_compat.h"

using namespace hooh;

struct ParsedUrl {
    std::string raw;
    std::string host;
    int port{9000};
    std::string path{"/"};
};

static bool parse_url(const std::string& input, ParsedUrl* out) {
    if (input.empty()) return false;
    std::string s = input;
    if (s.rfind("http://", 0) == 0) {
        s = s.substr(7);
    } else if (s.rfind("https://", 0) == 0) {
        // Spec says: "optional http:// prefix ignored"
        s = s.substr(8);
    }

    size_t slash_pos = s.find('/');
    std::string host_port = (slash_pos == std::string::npos) ? s : s.substr(0, slash_pos);
    std::string path = (slash_pos == std::string::npos) ? "/" : s.substr(slash_pos);

    std::string host;
    int port = 9000;

    size_t colon_pos = host_port.find(':');
    if (colon_pos != std::string::npos) {
        host = host_port.substr(0, colon_pos);
        std::string port_str = host_port.substr(colon_pos + 1);
        if (port_str.empty()) return false;
        try {
            port = std::stoi(port_str);
        } catch (...) {
            return false;
        }
        if (port <= 0 || port > 65535) return false;
    } else {
        host = host_port;
    }

    if (host.empty()) return false;

    out->raw = input;
    out->host = host;
    out->port = port;
    out->path = path;
    return true;
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    std::vector<std::string> raw_urls;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v") {
            verbose = true;
        } else {
            raw_urls.push_back(arg);
        }
    }

    if (raw_urls.empty()) {
        std::cerr << "Usage: bcurl [-v] <url>...\n";
        return 4; // Usage error
    }

    std::vector<ParsedUrl> urls;
    for (const auto& u : raw_urls) {
        ParsedUrl parsed;
        if (!parse_url(u, &parsed)) {
            std::cerr << "Malformed URL: " << u << "\n";
            return 4;
        }
        urls.push_back(parsed);
    }

    // All URLs in one invocation MUST share host and port, else usage error (§Appendix A)
    const std::string& target_host = urls[0].host;
    int target_port = urls[0].port;

    for (size_t i = 1; i < urls.size(); ++i) {
        if (urls[i].host != target_host || urls[i].port != target_port) {
            std::cerr << "All URLs in one invocation must share host and port.\n";
            return 4;
        }
    }

    if (!init_networking()) {
        std::cerr << "Failed to initialize networking\n";
        return 3;
    }

    // Connect to host:port
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    std::string port_str = std::to_string(target_port);
    if (getaddrinfo(target_host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        std::cerr << "Failed to resolve host: " << target_host << "\n";
        cleanup_networking();
        return 3;
    }

    socket_t sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == kInvalidSocket) {
        std::cerr << "Failed to create socket\n";
        freeaddrinfo(res);
        cleanup_networking();
        return 3;
    }

    if (connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
        std::cerr << "Failed to connect to " << target_host << ":" << target_port << "\n";
        freeaddrinfo(res);
        close_socket(sock);
        cleanup_networking();
        return 3;
    }
    freeaddrinfo(res);

    Session session(Role::Client, sock, verbose);

    // Preface exchange (§3)
    if (!session.do_preface_exchange()) {
        std::cerr << "Preface exchange failed\n";
        close_socket(sock);
        cleanup_networking();
        return 3;
    }

    int worst_severity = 0;
    uint32_t next_stream_id = 1;
    bool goaway_seen = false;

    for (size_t url_idx = 0; url_idx < urls.size(); ++url_idx) {
        if (goaway_seen) {
            worst_severity = std::max(worst_severity, 3);
            break;
        }

        if (next_stream_id > kMaxStreamId) {
            // Client exhausts 24-bit odd ID space: fails remaining URLs with severity 3 (§Appendix A)
            worst_severity = std::max(worst_severity, 3);
            break;
        }

        uint32_t stream_id = next_stream_id;
        next_stream_id += 2;

        session.open_client_stream(stream_id);

        // Build request HEADERS frame
        HeaderBlock req_block;
        req_block.method = "GET";
        req_block.path = urls[url_idx].path;

        std::vector<uint8_t> req_payload = encode_header_block(req_block, Direction::Request);

        FrameHeader req_hdr;
        req_hdr.length = static_cast<uint32_t>(req_payload.size());
        req_hdr.type = TYPE_HEADERS;
        req_hdr.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
        req_hdr.stream_id = stream_id;

        if (!session.send_frame(req_hdr, req_payload.data(), req_payload.size())) {
            std::cerr << "Transport failure sending request on stream " << stream_id << "\n";
            worst_severity = std::max(worst_severity, 3);
            break;
        }

        // Receive response loop for this stream
        bool stream_done = false;
        bool headers_seen = false;
        bool content_length_present = false;
        uint64_t expected_content_length = 0;
        uint64_t body_bytes_received = 0;

        while (!stream_done) {
            FrameHeader hdr;
            std::vector<uint8_t> payload;
            FrameAction action;

            // Timeout: 60 s while request is outstanding (§11)
            if (!session.read_and_classify_frame(&hdr, &payload, &action, 60000)) {
                std::cerr << "Transport failure or 60s timeout while waiting for response\n";
                worst_severity = std::max(worst_severity, 3);
                close_socket(sock);
                cleanup_networking();
                return worst_severity;
            }

            if (action.type == FrameActionType::ConnectionError) {
                session.send_goaway(0, ERR_PROTOCOL_ERROR);
                worst_severity = std::max(worst_severity, 3);
                close_socket(sock);
                cleanup_networking();
                return worst_severity;
            }

            if (action.type == FrameActionType::StreamError) {
                session.send_rst_stream(stream_id, ERR_PROTOCOL_ERROR);
                worst_severity = std::max(worst_severity, 3);
                session.close_stream(stream_id);
                break;
            }

            if (action.type == FrameActionType::Skip || action.type == FrameActionType::Ignore) {
                continue;
            }

            // Process response frame
            if (hdr.type == TYPE_PING) {
                FrameHeader pong_hdr;
                pong_hdr.length = 8;
                pong_hdr.type = TYPE_PONG;
                pong_hdr.flags = 0;
                pong_hdr.stream_id = 0;
                session.send_frame(pong_hdr, payload.data(), 8);
                continue;
            }

            if (hdr.type == TYPE_GOAWAY) {
                uint32_t last_id = load_le24(payload.data());
                if (last_id > session.highest_used_id()) {
                    session.send_goaway(0, ERR_PROTOCOL_ERROR);
                    worst_severity = std::max(worst_severity, 3);
                    close_socket(sock);
                    cleanup_networking();
                    return worst_severity;
                }
                if (last_id < stream_id) {
                    worst_severity = std::max(worst_severity, 3);
                    close_socket(sock);
                    cleanup_networking();
                    return worst_severity;
                } else {
                    // finish current stream normally, then close
                    goaway_seen = true;
                }
                continue;
            }

            if (hdr.type == TYPE_RST_STREAM) {
                worst_severity = std::max(worst_severity, 3);
                session.close_stream(stream_id);
                break;
            }

            if (hdr.type == TYPE_HEADERS) {
                headers_seen = true;
                auto dec = decode_header_block(payload.data(), payload.size(), Direction::Response);
                if (!std::holds_alternative<HeaderBlock>(dec)) {
                    session.send_rst_stream(stream_id, ERR_PROTOCOL_ERROR);
                    worst_severity = std::max(worst_severity, 3);
                    session.close_stream(stream_id);
                    break;
                }

                const auto& resp = std::get<HeaderBlock>(dec);
                int status = std::atoi(resp.status.c_str());

                // Status validation (§11 table)
                if (status < 100 || status > 599 || (status >= 100 && status < 200)) {
                    session.send_rst_stream(stream_id, ERR_PROTOCOL_ERROR);
                    worst_severity = std::max(worst_severity, 3);
                    session.close_stream(stream_id);
                    break;
                }

                if (resp.has_content_length) {
                    content_length_present = true;
                    expected_content_length = resp.content_length;
                }

                if (status >= 400 && status <= 499) {
                    worst_severity = std::max(worst_severity, 1);
                } else if (status >= 500 && status <= 599) {
                    worst_severity = std::max(worst_severity, 2);
                }

                if (hdr.flags & FLAG_END_STREAM) {
                    stream_done = true;
                    session.close_stream(stream_id);
                }
            } else if (hdr.type == TYPE_DATA) {
                if (!headers_seen) {
                    session.send_rst_stream(stream_id, ERR_PROTOCOL_ERROR);
                    worst_severity = std::max(worst_severity, 3);
                    session.close_stream(stream_id);
                    break;
                }

                // Deliver response body bytes to standard output (§8.1)
                std::fwrite(payload.data(), 1, payload.size(), stdout);
                std::fflush(stdout);

                body_bytes_received += payload.size();

                if (hdr.flags & FLAG_END_STREAM) {
                    if (content_length_present && body_bytes_received != expected_content_length) {
                        session.send_rst_stream(stream_id, ERR_PROTOCOL_ERROR);
                        worst_severity = std::max(worst_severity, 3);
                    }
                    stream_done = true;
                    session.close_stream(stream_id);
                }
            }
        }
    }

    close_socket(sock);
    cleanup_networking();
    return worst_severity;
}
