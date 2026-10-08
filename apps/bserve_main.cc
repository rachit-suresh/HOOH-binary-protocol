#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include "hooh/frame.h"
#include "hooh/headerblock.h"
#include "hooh/pathutil.h"
#include "hooh/session.h"
#include "hooh/fileserve.h"
#include "hooh/net_compat.h"

using namespace hooh;

static void handle_client(socket_t client_sock, std::string root_dir) {
    Session session(Role::Server, client_sock, false);

    // Step 0: Preface exchange (§3)
    if (!session.do_preface_exchange()) {
        close_socket(client_sock);
        return;
    }

    auto drain_and_close = [&session, client_sock]() {
        shutdown_write(client_sock);
        session.skip_bytes(1024 * 1024, 2000);
        close_socket(client_sock);
    };

    while (true) {
        // Check 60 s idle timeout (§12)
        int idle_secs = session.seconds_since_last_traffic();
        if (idle_secs >= 60) {
            session.send_goaway(session.last_committed_stream(), ERR_NO_ERROR);
            drain_and_close();
            return;
        }

        int timeout_ms = (60 - idle_secs) * 1000;
        if (timeout_ms <= 0) timeout_ms = 100;

        FrameHeader hdr;
        std::vector<uint8_t> payload;
        FrameAction action;

        if (!session.read_and_classify_frame(&hdr, &payload, &action, timeout_ms)) {
            // EOF or socket error -> silent close (§12)
            close_socket(client_sock);
            return;
        }

        if (action.type == FrameActionType::ConnectionError) {
            session.send_goaway(session.last_committed_stream(), normalize_error_code(action.status_or_code));
            drain_and_close();
            return;
        }

        if (action.type == FrameActionType::StreamError) {
            // Server stream-level error: discard stream's buffered state, send error response (§11)
            send_error_response(
                [&session](const FrameHeader& h, const uint8_t* p, size_t sz) {
                    return session.send_frame(h, p, sz);
                },
                hdr.stream_id, action.status_or_code);
            session.close_stream(hdr.stream_id);
            continue;
        }

        if (action.type == FrameActionType::Skip || action.type == FrameActionType::Ignore) {
            continue;
        }

        // Process frame (§11 Step 6 & Step 7)
        if (hdr.type == TYPE_PING) {
            // Answer PING with PONG echoing challenge (§8.4)
            FrameHeader pong_hdr;
            pong_hdr.length = 8;
            pong_hdr.type = TYPE_PONG;
            pong_hdr.flags = 0;
            pong_hdr.stream_id = 0;
            session.send_frame(pong_hdr, payload.data(), 8);
            continue;
        }

        if (hdr.type == TYPE_PONG) {
            // Unsolicited or unexpected PONG
            if (!session.has_outstanding_ping()) {
                session.send_goaway(session.last_committed_stream(), ERR_PROTOCOL_ERROR);
                drain_and_close();
                return;
            }
            uint64_t chal = load_le64(payload.data());
            if (chal != session.outstanding_ping()) {
                session.send_goaway(session.last_committed_stream(), ERR_PROTOCOL_ERROR);
                drain_and_close();
                return;
            }
            session.clear_outstanding_ping();
            continue;
        }

        if (hdr.type == TYPE_GOAWAY) {
            // Drain and close
            close_socket(client_sock);
            return;
        }

        if (hdr.type == TYPE_RST_STREAM) {
            // RST on the open stream aborts it (§8.3)
            session.abort_stream(hdr.stream_id);
            continue;
        }

        StreamState* cur = session.current_stream();
        if (!cur) {
            continue;
        }

        if (hdr.type == TYPE_HEADERS) {
            cur->headers_payload = payload;
            cur->headers_flags = hdr.flags;
            if (hdr.flags & FLAG_END_STREAM) {
                cur->end_stream_in = true;
            }
        } else if (hdr.type == TYPE_DATA) {
            // Request DATA is discarded by Length in v1 (§8.1)
            cur->body_bytes_seen += hdr.length;
            if (hdr.flags & FLAG_END_STREAM) {
                cur->end_stream_in = true;
            }
        }

        // Step 7: payload grammar evaluated once END_STREAM is seen (§8.2, §11 Step 7)
        if (cur->end_stream_in) {
            uint32_t sid = cur->id;

            // 1. Decode header block
            auto dec = decode_header_block(
                cur->headers_payload.data(), cur->headers_payload.size(), Direction::Request);

            if (!std::holds_alternative<HeaderBlock>(dec)) {
                send_error_response(
                    [&session](const FrameHeader& h, const uint8_t* p, size_t sz) {
                        return session.send_frame(h, p, sz);
                    },
                    sid, 400);
                session.close_stream(sid);
                continue;
            }

            const auto& req = std::get<HeaderBlock>(dec);

            // 2. Content-length check
            if (req.has_content_length && req.content_length != cur->body_bytes_seen) {
                send_error_response(
                    [&session](const FrameHeader& h, const uint8_t* p, size_t sz) {
                        return session.send_frame(h, p, sz);
                    },
                    sid, 400);
                session.close_stream(sid);
                continue;
            }

            // 3. Method check (§10)
            if (req.method != "GET") {
                if (req.method == "HEAD" || req.method == "POST" || req.method == "PUT" ||
                    req.method == "DELETE" || req.method == "CONNECT" || req.method == "OPTIONS" ||
                    req.method == "PATCH" || req.method == "TRACE") {
                    send_error_response(
                        [&session](const FrameHeader& h, const uint8_t* p, size_t sz) {
                            return session.send_frame(h, p, sz);
                        },
                        sid, 405);
                } else {
                    send_error_response(
                        [&session](const FrameHeader& h, const uint8_t* p, size_t sz) {
                            return session.send_frame(h, p, sz);
                        },
                        sid, 501);
                }
                session.close_stream(sid);
                continue;
            }

            // 4. Path grammar check (§10 (a), (b), (c))
            std::string clean_path;
            if (check_path_grammar(req.path, &clean_path) != PathGrammarResult::Ok) {
                send_error_response(
                    [&session](const FrameHeader& h, const uint8_t* p, size_t sz) {
                        return session.send_frame(h, p, sz);
                    },
                    sid, 400);
                session.close_stream(sid);
                continue;
            }

            // 5. Lexical normalization and dotfile check (§10 (d), (e))
            std::string norm_path;
            std::string err_reason;
            if (!normalize_lexical_path(clean_path, &norm_path, &err_reason)) {
                std::cerr << "Path check failed (" << err_reason << "): " << req.path << "\n";
                send_error_response(
                    [&session](const FrameHeader& h, const uint8_t* p, size_t sz) {
                        return session.send_frame(h, p, sz);
                    },
                    sid, 404);
                session.close_stream(sid);
                continue;
            }

            // 6. Filesystem resolution & containment (§10 (f), (g))
            ResolvedFile file;
            if (resolve_under_root(root_dir, norm_path, &file, &err_reason) != PathResolveResult::Ok) {
                std::cerr << "Resolution failed (" << err_reason << "): " << req.path << "\n";
                send_error_response(
                    [&session](const FrameHeader& h, const uint8_t* p, size_t sz) {
                        return session.send_frame(h, p, sz);
                    },
                    sid, 404);
                session.close_stream(sid);
                continue;
            }

            // Success -> 200
            session.set_last_committed_stream(sid);
            serve_file_response(
                [&session](const FrameHeader& h, const uint8_t* p, size_t sz) {
                    return session.send_frame(h, p, sz);
                },
                sid, file);
            session.close_stream(sid);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: bserve <root> <port>\n";
        return 4;
    }

    std::string root = argv[1];
    int port = std::atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        std::cerr << "Invalid port: " << argv[2] << "\n";
        return 4;
    }

    if (!init_networking()) {
        std::cerr << "Failed to initialize networking\n";
        return 3;
    }

    socket_t listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == kInvalidSocket) {
        std::cerr << "Failed to create socket\n";
        cleanup_networking();
        return 3;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "Failed to bind to port " << port << "\n";
        close_socket(listen_sock);
        cleanup_networking();
        return 3;
    }

    if (listen(listen_sock, 128) != 0) {
        std::cerr << "Failed to listen on socket\n";
        close_socket(listen_sock);
        cleanup_networking();
        return 3;
    }

    std::cerr << "bserve running on port " << port << " root=" << root << "\n";

    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        socket_t client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client_sock == kInvalidSocket) {
            continue;
        }

        std::thread([client_sock, root]() {
            handle_client(client_sock, root);
        }).detach();
    }

    close_socket(listen_sock);
    cleanup_networking();
    return 0;
}
