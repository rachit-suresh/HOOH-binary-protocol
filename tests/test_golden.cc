#include <cassert>
#include <iostream>
#include <vector>
#include <cstring>
#include "hooh/frame.h"
#include "hooh/headerblock.h"

using namespace hooh;

int main() {
    std::cout << "Running HOOH §15 Golden Test...\n";

    // 1. Preface check
    const uint8_t expected_preface[10] = {
        0x48, 0x65, 0x4c, 0x6c, 0x4f, 0x4f, 0x6c, 0x4c, 0x65, 0x48
    };
    assert(std::memcmp(kPreface, expected_preface, 10) == 0);

    // 2. Client HEADERS frame check (All 5 Client Headers)
    // 3c 00 00 | 13 | 01 00 00
    // 01 03 00 47 45 54
    // 02 0b 00 2f 69 6e 64 65 78 2e 68 74 6d 6c
    // 04 0e 00 31 32 37 2e 30 2e 30 2e 31 3a 39 30 38 30
    // 05 0e 00 68 6f 6f 68 2d 62 63 75 72 6c 2f 31 2e 30
    // 0a 03 00 2a 2f 2a
    const uint8_t golden_req_bytes[] = {
        0x3c, 0x00, 0x00, 0x13, 0x01, 0x00, 0x00, // header: len=60, type=1, flags=3, stream=1
        0x01, 0x03, 0x00, 'G', 'E', 'T',
        0x02, 0x0b, 0x00, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
        0x04, 0x0e, 0x00, '1', '2', '7', '.', '0', '.', '0', '.', '1', ':', '9', '0', '8', '0',
        0x05, 0x0e, 0x00, 'h', 'o', 'o', 'h', '-', 'b', 'c', 'u', 'r', 'l', '/', '1', '.', '0',
        0x0a, 0x03, 0x00, '*', '/', '*'
    };

    FrameHeader req_hdr = unpack_header(golden_req_bytes);
    assert(req_hdr.length == 60);
    assert(req_hdr.type == TYPE_HEADERS);
    assert(req_hdr.flags == (FLAG_END_STREAM | FLAG_END_HEADERS));
    assert(req_hdr.stream_id == 1);

    auto dec_req = decode_header_block(golden_req_bytes + 7, req_hdr.length, Direction::Request);
    assert(std::holds_alternative<HeaderBlock>(dec_req));
    const auto& req_blk = std::get<HeaderBlock>(dec_req);
    assert(req_blk.method == "GET");
    assert(req_blk.path == "/index.html");
    assert(req_blk.get_header("host") == "127.0.0.1:9080");
    assert(req_blk.get_header("user-agent") == "hooh-bcurl/1.0");
    assert(req_blk.get_header("accept") == "*/*");

    // Test encoding generates the exact wire bytes
    HeaderBlock client_to_encode;
    client_to_encode.method = "GET";
    client_to_encode.path = "/index.html";
    client_to_encode.set_header("host", "127.0.0.1:9080");
    client_to_encode.set_header("user-agent", "hooh-bcurl/1.0");
    client_to_encode.set_header("accept", "*/*");

    std::vector<uint8_t> encoded_req_payload = encode_header_block(client_to_encode, Direction::Request);
    assert(encoded_req_payload.size() == 60);
    assert(std::memcmp(encoded_req_payload.data(), golden_req_bytes + 7, 60) == 0);

    uint8_t enc_req_hdr[7];
    FrameHeader h_req{60, TYPE_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1};
    pack_header(h_req, enc_req_hdr);
    assert(std::memcmp(enc_req_hdr, golden_req_bytes, 7) == 0);

    // 3. Server HEADERS frame check (All 5 Server Headers)
    // 48 00 00 | 12 | 01 00 00
    // 03 03 00 32 30 30
    // 06 0f 00 68 6f 6f 68 2d 62 73 65 72 76 65 2f 31 2e 30
    // 07 1d 00 46 72 69 2c 20 30 39 20 4f 63 74 20 32 30 32 36 20 31 32 3a 30 30 3a 30 30 20 47 4d 54
    // 08 09 00 74 65 78 74 2f 68 74 6d 6c
    // 09 01 00 35
    const uint8_t golden_resp_bytes[] = {
        0x48, 0x00, 0x00, 0x12, 0x01, 0x00, 0x00, // header: len=72, type=1, flags=2, stream=1
        0x03, 0x03, 0x00, '2', '0', '0',
        0x06, 0x0f, 0x00, 'h', 'o', 'o', 'h', '-', 'b', 's', 'e', 'r', 'v', 'e', '/', '1', '.', '0',
        0x07, 0x1d, 0x00, 'F', 'r', 'i', ',', ' ', '0', '9', ' ', 'O', 'c', 't', ' ', '2', '0', '2', '6', ' ', '1', '2', ':', '0', '0', ':', '0', '0', ' ', 'G', 'M', 'T',
        0x08, 0x09, 0x00, 't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l',
        0x09, 0x01, 0x00, '5'
    };

    FrameHeader resp_hdr = unpack_header(golden_resp_bytes);
    assert(resp_hdr.length == 72);
    assert(resp_hdr.type == TYPE_HEADERS);
    assert(resp_hdr.flags == FLAG_END_HEADERS);
    assert(resp_hdr.stream_id == 1);

    auto dec_resp = decode_header_block(golden_resp_bytes + 7, resp_hdr.length, Direction::Response);
    assert(std::holds_alternative<HeaderBlock>(dec_resp));
    const auto& resp_blk = std::get<HeaderBlock>(dec_resp);
    assert(resp_blk.status == "200");
    assert(resp_blk.get_header("server") == "hooh-bserve/1.0");
    assert(resp_blk.get_header("date") == "Fri, 09 Oct 2026 12:00:00 GMT");
    assert(resp_blk.get_header("content-type") == "text/html");
    assert(resp_blk.get_header("content-length") == "5");

    HeaderBlock server_to_encode;
    server_to_encode.status = "200";
    server_to_encode.set_header("server", "hooh-bserve/1.0");
    server_to_encode.set_header("date", "Fri, 09 Oct 2026 12:00:00 GMT");
    server_to_encode.set_header("content-type", "text/html");
    server_to_encode.set_header("content-length", "5");

    std::vector<uint8_t> encoded_resp_payload = encode_header_block(server_to_encode, Direction::Response);
    assert(encoded_resp_payload.size() == 72);
    assert(std::memcmp(encoded_resp_payload.data(), golden_resp_bytes + 7, 72) == 0);

    uint8_t enc_resp_hdr[7];
    FrameHeader h_resp{72, TYPE_HEADERS, FLAG_END_HEADERS, 1};
    pack_header(h_resp, enc_resp_hdr);
    assert(std::memcmp(enc_resp_hdr, golden_resp_bytes, 7) == 0);

    // 4. Server DATA frame check
    // 05 00 00 | 01 | 01 00 00 | 68 65 6c 6c 6f
    const uint8_t golden_data_bytes[] = {
        0x05, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
        'h', 'e', 'l', 'l', 'o'
    };

    FrameHeader data_hdr = unpack_header(golden_data_bytes);
    assert(data_hdr.length == 5);
    assert(data_hdr.type == TYPE_DATA);
    assert(data_hdr.flags == FLAG_END_STREAM);
    assert(data_hdr.stream_id == 1);
    assert(std::memcmp(golden_data_bytes + 7, "hello", 5) == 0);

    std::cout << "HOOH §15 Golden Test Passed 100% Successfully!\n";
    return 0;
}
