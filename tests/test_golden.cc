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

    // 2. Client HEADERS frame check
    // 20 00 00 | 13 | 01 00 00
    // 01 03 00 47 45 54
    // 02 0b 00 2f 69 6e 64 65 78 2e 68 74 6d 6c
    // 00 06 78 2d 74 65 73 74 02 00 34 32
    const uint8_t golden_req_bytes[] = {
        0x20, 0x00, 0x00, 0x13, 0x01, 0x00, 0x00, // header: len=32, type=1, flags=3, stream=1
        0x01, 0x03, 0x00, 'G', 'E', 'T',
        0x02, 0x0b, 0x00, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
        0x00, 0x06, 'x', '-', 't', 'e', 's', 't', 0x02, 0x00, '4', '2'
    };

    FrameHeader req_hdr = unpack_header(golden_req_bytes);
    assert(req_hdr.length == 32);
    assert(req_hdr.type == TYPE_HEADERS);
    assert(req_hdr.flags == (FLAG_END_STREAM | FLAG_END_HEADERS));
    assert(req_hdr.stream_id == 1);

    auto dec_req = decode_header_block(golden_req_bytes + 7, req_hdr.length, Direction::Request);
    assert(std::holds_alternative<HeaderBlock>(dec_req));
    const auto& req_blk = std::get<HeaderBlock>(dec_req);
    assert(req_blk.method == "GET");
    assert(req_blk.path == "/index.html");
    assert(req_blk.get_header("x-test") == "42");

    // Test encoding generates the exact wire bytes
    HeaderBlock client_to_encode;
    client_to_encode.method = "GET";
    client_to_encode.path = "/index.html";
    client_to_encode.fields.push_back({"x-test", "42", 0});

    std::vector<uint8_t> encoded_req_payload = encode_header_block(client_to_encode, Direction::Request);
    assert(encoded_req_payload.size() == 32);
    assert(std::memcmp(encoded_req_payload.data(), golden_req_bytes + 7, 32) == 0);

    uint8_t enc_req_hdr[7];
    FrameHeader h_req{32, TYPE_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1};
    pack_header(h_req, enc_req_hdr);
    assert(std::memcmp(enc_req_hdr, golden_req_bytes, 7) == 0);

    // 3. Server HEADERS frame check
    // 12 00 00 | 12 | 01 00 00
    // 03 03 00 32 30 30
    // 08 09 00 74 65 78 74 2f 68 74 6d 6c
    const uint8_t golden_resp_bytes[] = {
        0x12, 0x00, 0x00, 0x12, 0x01, 0x00, 0x00, // header: len=18, type=1, flags=2, stream=1
        0x03, 0x03, 0x00, '2', '0', '0',
        0x08, 0x09, 0x00, 't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l'
    };

    FrameHeader resp_hdr = unpack_header(golden_resp_bytes);
    assert(resp_hdr.length == 18);
    assert(resp_hdr.type == TYPE_HEADERS);
    assert(resp_hdr.flags == FLAG_END_HEADERS);
    assert(resp_hdr.stream_id == 1);

    auto dec_resp = decode_header_block(golden_resp_bytes + 7, resp_hdr.length, Direction::Response);
    assert(std::holds_alternative<HeaderBlock>(dec_resp));
    const auto& resp_blk = std::get<HeaderBlock>(dec_resp);
    assert(resp_blk.status == "200");
    assert(resp_blk.get_header("content-type") == "text/html");

    HeaderBlock server_to_encode;
    server_to_encode.status = "200";
    server_to_encode.set_header("content-type", "text/html");

    std::vector<uint8_t> encoded_resp_payload = encode_header_block(server_to_encode, Direction::Response);
    assert(encoded_resp_payload.size() == 18);
    assert(std::memcmp(encoded_resp_payload.data(), golden_resp_bytes + 7, 18) == 0);

    uint8_t enc_resp_hdr[7];
    FrameHeader h_resp{18, TYPE_HEADERS, FLAG_END_HEADERS, 1};
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
