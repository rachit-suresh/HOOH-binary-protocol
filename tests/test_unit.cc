#include <cassert>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <filesystem>
#include <fstream>
#include "hooh/frame.h"
#include "hooh/headerblock.h"
#include "hooh/pathutil.h"

using namespace hooh;

void test_frame_codec() {
    std::cout << "[TEST] Frame Codec...\n";

    // 1. Pack and unpack header
    FrameHeader h1{16384, TYPE_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1};
    uint8_t raw[7];
    pack_header(h1, raw);

    FrameHeader h2 = unpack_header(raw);
    assert(h2.length == 16384);
    assert(h2.type == TYPE_HEADERS);
    assert(h2.flags == (FLAG_END_HEADERS | FLAG_END_STREAM));
    assert(h2.stream_id == 1);

    // 2. Boundary length values
    FrameHeader h_max{0x00FFFFFF, TYPE_DATA, 0, 0x00FFFFFF};
    pack_header(h_max, raw);
    FrameHeader h_max_out = unpack_header(raw);
    assert(h_max_out.length == 0x00FFFFFF);
    assert(h_max_out.stream_id == 0x00FFFFFF);

    // 3. Error code normalization
    assert(normalize_error_code(0) == ERR_NO_ERROR);
    assert(normalize_error_code(1) == ERR_PROTOCOL_ERROR);
    assert(normalize_error_code(2) == ERR_CANCELLED);
    assert(normalize_error_code(3) == ERR_INTERNAL);
    assert(normalize_error_code(4) == ERR_PROTOCOL_ERROR);
    assert(normalize_error_code(255) == ERR_PROTOCOL_ERROR);

    // 4. Little endian load/store
    uint8_t buf[8];
    store_le16(buf, 0x1234);
    assert(buf[0] == 0x34 && buf[1] == 0x12);
    assert(load_le16(buf) == 0x1234);

    store_le24(buf, 0x123456);
    assert(buf[0] == 0x56 && buf[1] == 0x34 && buf[2] == 0x12);
    assert(load_le24(buf) == 0x123456);

    store_le64(buf, 0x0102030405060708ULL);
    assert(load_le64(buf) == 0x0102030405060708ULL);

    std::cout << "  -> Passed!\n";
}

void test_header_block_codec() {
    std::cout << "[TEST] Header Block Codec & Grammar...\n";

    // 1. Valid Request
    HeaderBlock req;
    req.method = "GET";
    req.path = "/hello.txt";
    req.fields.push_back({"host", "example.com", HDR_HOST});
    req.fields.push_back({"user-agent", "bcurl/1.0", HDR_USER_AGENT});

    auto enc = encode_header_block(req, Direction::Request);
    auto dec = decode_header_block(enc.data(), enc.size(), Direction::Request);
    assert(std::holds_alternative<HeaderBlock>(dec));
    const auto& dec_req = std::get<HeaderBlock>(dec);
    assert(dec_req.method == "GET");
    assert(dec_req.path == "/hello.txt");
    assert(dec_req.get_header("host") == "example.com");
    assert(dec_req.get_header("user-agent") == "bcurl/1.0");

    // 2. Valid Response
    HeaderBlock resp;
    resp.status = "200";
    resp.set_header("content-type", "text/html");
    resp.set_header("content-length", "42");

    auto enc_resp = encode_header_block(resp, Direction::Response);
    auto dec_resp_res = decode_header_block(enc_resp.data(), enc_resp.size(), Direction::Response);
    assert(std::holds_alternative<HeaderBlock>(dec_resp_res));
    const auto& dec_resp = std::get<HeaderBlock>(dec_resp_res);
    assert(dec_resp.status == "200");
    assert(dec_resp.has_content_length);
    assert(dec_resp.content_length == 42);
    assert(dec_resp.get_header("content-type") == "text/html");

    // 3. Overrun error
    uint8_t bad_overrun[] = {HDR_METHOD, 0x10, 0x00, 'G', 'E'}; // declared 16 B, only 2 provided
    auto dec_err1 = decode_header_block(bad_overrun, sizeof(bad_overrun), Direction::Request);
    assert(std::holds_alternative<BlockError>(dec_err1));
    assert(std::get<BlockError>(dec_err1) == BlockError::MalformedGrammar);

    // 4. Zero-length literal name error
    uint8_t zero_lit[] = {HDR_LITERAL, 0x00, 0x01, 0x00, 'x'};
    auto dec_err2 = decode_header_block(zero_lit, sizeof(zero_lit), Direction::Request);
    assert(std::holds_alternative<BlockError>(dec_err2));
    assert(std::get<BlockError>(dec_err2) == BlockError::MalformedGrammar);

    // 5. Out of range static table index (0x0B)
    uint8_t bad_idx[] = {0x0B, 0x01, 0x00, 'x'};
    auto dec_err3 = decode_header_block(bad_idx, sizeof(bad_idx), Direction::Request);
    assert(std::holds_alternative<BlockError>(dec_err3));
    assert(std::get<BlockError>(dec_err3) == BlockError::MalformedGrammar);

    // 6. Unknown pseudo-header (:custom)
    uint8_t unk_pseudo[] = {
        HDR_LITERAL, 0x07, ':', 'c', 'u', 's', 't', 'o', 'm',
        0x01, 0x00, 'v'
    };
    auto dec_err4 = decode_header_block(unk_pseudo, sizeof(unk_pseudo), Direction::Request);
    assert(std::holds_alternative<BlockError>(dec_err4));
    assert(std::get<BlockError>(dec_err4) == BlockError::UnknownPseudo);

    // 7. Unknown regular header: MUST be ignored (§9)
    // Encode valid :method and :path, plus an unknown literal regular header
    HeaderBlock req_with_custom;
    req_with_custom.method = "GET";
    req_with_custom.path = "/";
    req_with_custom.fields.push_back({"x-unknown-ext", "custom_val", 0});
    auto enc_custom = encode_header_block(req_with_custom, Direction::Request);
    auto dec_custom = decode_header_block(enc_custom.data(), enc_custom.size(), Direction::Request);
    assert(std::holds_alternative<HeaderBlock>(dec_custom));

    // 8. Wrong direction: :status in request
    uint8_t status_in_req[] = {
        HDR_STATUS, 0x03, 0x00, '2', '0', '0',
        HDR_METHOD, 0x03, 0x00, 'G', 'E', 'T',
        HDR_PATH, 0x01, 0x00, '/'
    };
    auto dec_err5 = decode_header_block(status_in_req, sizeof(status_in_req), Direction::Request);
    assert(std::holds_alternative<BlockError>(dec_err5));
    assert(std::get<BlockError>(dec_err5) == BlockError::WrongDirection);

    // 9. Pseudo after regular header
    uint8_t pseudo_after_reg[] = {
        HDR_METHOD, 0x03, 0x00, 'G', 'E', 'T',
        HDR_HOST, 0x03, 0x00, 'f', 'o', 'o',
        HDR_PATH, 0x01, 0x00, '/'
    };
    auto dec_err6 = decode_header_block(pseudo_after_reg, sizeof(pseudo_after_reg), Direction::Request);
    assert(std::holds_alternative<BlockError>(dec_err6));
    assert(std::get<BlockError>(dec_err6) == BlockError::PseudoAfterRegular);

    // 10. Duplicate pseudo-header
    uint8_t dup_pseudo[] = {
        HDR_METHOD, 0x03, 0x00, 'G', 'E', 'T',
        HDR_METHOD, 0x03, 0x00, 'G', 'E', 'T',
        HDR_PATH, 0x01, 0x00, '/'
    };
    auto dec_err7 = decode_header_block(dup_pseudo, sizeof(dup_pseudo), Direction::Request);
    assert(std::holds_alternative<BlockError>(dec_err7));
    assert(std::get<BlockError>(dec_err7) == BlockError::DuplicatePseudo);

    // 11. Missing pseudo-header
    uint8_t missing_path[] = {
        HDR_METHOD, 0x03, 0x00, 'G', 'E', 'T'
    };
    auto dec_err8 = decode_header_block(missing_path, sizeof(missing_path), Direction::Request);
    assert(std::holds_alternative<BlockError>(dec_err8));
    assert(std::get<BlockError>(dec_err8) == BlockError::MissingPseudo);

    // 12. Invalid status (not 3 digits)
    uint8_t bad_status[] = {
        HDR_STATUS, 0x04, 0x00, '2', '0', '0', '0'
    };
    auto dec_err9 = decode_header_block(bad_status, sizeof(bad_status), Direction::Response);
    assert(std::holds_alternative<BlockError>(dec_err9));
    assert(std::get<BlockError>(dec_err9) == BlockError::InvalidStatus);

    // 13. Invalid content-length (negative / non-digit)
    uint8_t bad_cl[] = {
        HDR_STATUS, 0x03, 0x00, '2', '0', '0',
        HDR_CONTENT_LENGTH, 0x02, 0x00, '-', '5'
    };
    auto dec_err10 = decode_header_block(bad_cl, sizeof(bad_cl), Direction::Response);
    assert(std::holds_alternative<BlockError>(dec_err10));
    assert(std::get<BlockError>(dec_err10) == BlockError::InvalidContentLength);

    // 14. Duplicate regular header: last wins
    HeaderBlock dup_reg;
    dup_reg.status = "200";
    dup_reg.fields.push_back({"server", "first", HDR_SERVER});
    dup_reg.fields.push_back({"server", "second", HDR_SERVER});
    auto enc_dup = encode_header_block(dup_reg, Direction::Response);
    auto dec_dup_res = decode_header_block(enc_dup.data(), enc_dup.size(), Direction::Response);
    assert(std::holds_alternative<HeaderBlock>(dec_dup_res));
    const auto& dec_dup = std::get<HeaderBlock>(dec_dup_res);
    assert(dec_dup.get_header("server") == "second");

    std::cout << "  -> Passed!\n";
}

void test_path_semantics() {
    std::cout << "[TEST] Path Grammar & Normalization...\n";

    // 1. Query strip
    std::string clean;
    assert(check_path_grammar("/index.html?test=1&b=2", &clean) == PathGrammarResult::Ok);
    assert(clean == "/index.html");

    // 2. NUL byte in path
    std::string nul_path = "/bad\0path";
    nul_path.resize(9);
    assert(check_path_grammar(nul_path, &clean) == PathGrammarResult::Invalid);

    // 3. Leading slash check
    assert(check_path_grammar("no/slash", &clean) == PathGrammarResult::Invalid);
    assert(check_path_grammar("", &clean) == PathGrammarResult::Invalid);

    // 4. Lexical normalization
    std::string norm;
    std::string reason;

    // Normal path
    assert(normalize_lexical_path("/a/b/c", &norm, &reason));
    assert(norm == "/a/b/c");

    // Collapsing slashes and resolving . and ..
    assert(normalize_lexical_path("//a///./b/../c/", &norm, &reason));
    assert(norm == "/a/c");

    // / stays /
    assert(normalize_lexical_path("/", &norm, &reason));
    assert(norm == "/");
    assert(normalize_lexical_path("///", &norm, &reason));
    assert(norm == "/");

    // /index.html/ becomes /index.html
    assert(normalize_lexical_path("/index.html/", &norm, &reason));
    assert(norm == "/index.html");

    // Lexical root escape yields 404 (returns false)
    assert(!normalize_lexical_path("/../", &norm, &reason));
    assert(!normalize_lexical_path("/a/../../", &norm, &reason));

    // Dot component yields 404
    assert(!normalize_lexical_path("/.secret", &norm, &reason));
    assert(!normalize_lexical_path("/dir/.git/config", &norm, &reason));

    // 5. Filesystem resolution & containment
    std::filesystem::path test_dir = "test_unit_root";
    std::filesystem::create_directories(test_dir / "subdir");
    {
        std::ofstream ofs(test_dir / "index.html");
        ofs << "Root index";
    }
    {
        std::ofstream ofs(test_dir / "subdir" / "index.html");
        ofs << "Subdir index";
    }
    {
        std::ofstream ofs(test_dir / "file.txt");
        ofs << "Plain file";
    }

    ResolvedFile rf;
    // Resolve / -> test_unit_root/index.html
    assert(resolve_under_root(test_dir.string(), "/", &rf, &reason) == PathResolveResult::Ok);
    assert(rf.mime_type == "text/html");

    // Resolve /subdir -> test_unit_root/subdir/index.html
    assert(resolve_under_root(test_dir.string(), "/subdir", &rf, &reason) == PathResolveResult::Ok);
    assert(rf.mime_type == "text/html");

    // Resolve /file.txt -> test_unit_root/file.txt
    assert(resolve_under_root(test_dir.string(), "/file.txt", &rf, &reason) == PathResolveResult::Ok);
    assert(rf.mime_type == "text/plain");

    // Missing file -> 404
    assert(resolve_under_root(test_dir.string(), "/not_found.html", &rf, &reason) == PathResolveResult::NotFound);

    // Clean up
    std::filesystem::remove_all(test_dir);

    std::cout << "  -> Passed!\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "       HOOH v1 Unit Test Suite          \n";
    std::cout << "========================================\n";

    test_frame_codec();
    test_header_block_codec();
    test_path_semantics();

    std::cout << "========================================\n";
    std::cout << " All Unit Tests Passed Successfully!    \n";
    std::cout << "========================================\n";
    return 0;
}
