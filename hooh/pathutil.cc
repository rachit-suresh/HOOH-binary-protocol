#include "pathutil.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace hooh {

namespace fs = std::filesystem;

PathGrammarResult check_path_grammar(const std::string& raw_path, std::string* clean_path) {
    if (raw_path.empty()) {
        return PathGrammarResult::Invalid;
    }

    // (a) bytes from first '?' onward are discarded
    size_t qpos = raw_path.find('?');
    std::string s = (qpos == std::string::npos) ? raw_path : raw_path.substr(0, qpos);

    // (b) a NUL byte in remainder is malformed
    if (s.find('\0') != std::string::npos) {
        return PathGrammarResult::Invalid;
    }

    // (c) remainder MUST begin with '/'
    if (s.empty() || s[0] != '/') {
        return PathGrammarResult::Invalid;
    }

    if (clean_path) {
        *clean_path = s;
    }
    return PathGrammarResult::Ok;
}

bool normalize_lexical_path(const std::string& clean_path, std::string* normalized_path, std::string* error_reason) {
    // (d) resolve '.' and '..', collapse '//', remove trailing slash ('/' stays '/')
    std::vector<std::string> parts;
    size_t i = 0;
    size_t len = clean_path.size();

    while (i < len) {
        while (i < len && clean_path[i] == '/') {
            ++i;
        }
        if (i >= len) break;
        size_t start = i;
        while (i < len && clean_path[i] != '/') {
            ++i;
        }
        std::string part = clean_path.substr(start, i - start);
        if (part == ".") {
            continue;
        } else if (part == "..") {
            if (parts.empty()) {
                if (error_reason) *error_reason = "path escapes root lexically";
                return false; // escapes root -> 404
            }
            parts.pop_back();
        } else {
            // (e) any remaining path component beginning with '.' yields 404
            if (!part.empty() && part[0] == '.') {
                if (error_reason) *error_reason = "component begins with dot";
                return false;
            }
            parts.push_back(part);
        }
    }

    std::string res;
    if (parts.empty()) {
        res = "/";
    } else {
        for (const auto& p : parts) {
            res += "/" + p;
        }
    }

    if (normalized_path) {
        *normalized_path = res;
    }
    return true;
}

PathResolveResult resolve_under_root(
    const std::string& root_dir,
    const std::string& normalized_path,
    ResolvedFile* out_file,
    std::string* error_reason) {

    std::error_code ec;
    fs::path root_p = fs::canonical(fs::path(root_dir), ec);
    if (ec) {
        if (error_reason) *error_reason = "invalid root dir: " + ec.message();
        return PathResolveResult::NotFound;
    }

    std::string root_str = root_p.generic_string();

    // relative path without leading '/'
    std::string rel = (normalized_path.size() > 1 && normalized_path[0] == '/')
                      ? normalized_path.substr(1)
                      : "";

    fs::path target_p = root_p;
    if (!rel.empty()) {
        target_p /= fs::path(rel);
    }

    fs::path resolved_p = fs::canonical(target_p, ec);
    if (ec) {
        // Might not exist or might be unreadable
        if (error_reason) *error_reason = "target does not exist or unresolvable: " + ec.message();
        return PathResolveResult::NotFound;
    }

    // Component-wise containment check (§10 (f))
    std::string resolved_str = resolved_p.generic_string();
    bool contained = false;
    if (resolved_str == root_str) {
        contained = true;
    } else {
        std::string prefix = root_str;
        if (prefix.back() != '/') {
            prefix += '/';
        }
        if (resolved_str.rfind(prefix, 0) == 0) {
            contained = true;
        }
    }

    if (!contained) {
        if (error_reason) *error_reason = "path escaped root after symlink resolution";
        return PathResolveResult::NotFound;
    }

    // Re-apply dot rule to resolved path
    std::string sub = resolved_str.substr(root_str.size());
    std::stringstream ss(sub);
    std::string seg;
    while (std::getline(ss, seg, '/')) {
        if (!seg.empty() && seg[0] == '.') {
            if (error_reason) *error_reason = "resolved symlink component begins with dot";
            return PathResolveResult::NotFound;
        }
    }

    // (g) resolved path MUST be regular file, or directory served as <dir>/index.html
    if (fs::is_directory(resolved_p, ec)) {
        fs::path index_p = resolved_p / "index.html";
        fs::path resolved_index = fs::canonical(index_p, ec);
        if (ec || !fs::is_regular_file(resolved_index, ec)) {
            if (error_reason) *error_reason = "directory missing index.html";
            return PathResolveResult::NotFound;
        }
        resolved_p = resolved_index;
    } else if (!fs::is_regular_file(resolved_p, ec)) {
        if (error_reason) *error_reason = "not a regular file";
        return PathResolveResult::NotFound;
    }

    // Check readability and determine size
    std::ifstream ifs(resolved_p, std::ios::binary);
    if (!ifs.is_open()) {
        if (error_reason) *error_reason = "file unreadable";
        return PathResolveResult::NotFound;
    }

    uintmax_t sz = fs::file_size(resolved_p, ec);
    if (ec) {
        if (error_reason) *error_reason = "cannot read file size";
        return PathResolveResult::NotFound;
    }

    if (out_file) {
        out_file->canonical_path = resolved_p.string();
        out_file->size = sz;
        out_file->mime_type = get_mime_type(resolved_p.string());
    }

    return PathResolveResult::Ok;
}

std::string get_mime_type(const std::string& path) {
    size_t dot = path.rfind('.');
    if (dot == std::string::npos) {
        return "application/octet-stream";
    }
    std::string ext = path.substr(dot);
    for (char& c : ext) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    if (ext == ".html" || ext == ".htm") return "text/html";
    if (ext == ".txt") return "text/plain";
    if (ext == ".css") return "text/css";
    if (ext == ".js") return "application/javascript";
    if (ext == ".json") return "application/json";
    if (ext == ".png") return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".gif") return "image/gif";
    if (ext == ".svg") return "image/svg+xml";
    if (ext == ".pdf") return "application/pdf";
    return "application/octet-stream";
}

} // namespace hooh
