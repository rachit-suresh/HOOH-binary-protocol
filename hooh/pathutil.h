#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace hooh {

enum class PathGrammarResult {
    Ok,
    Invalid
};

enum class PathResolveResult {
    Ok,
    NotFound, // 404 (covers missing, escaped, dotfile, special, unreadable)
};

struct ResolvedFile {
    std::string canonical_path;
    uint64_t size{0};
    std::string mime_type;
};

// Step 1: Query strip and Grammar check (§10)
// Returns grammar result and path without query string.
PathGrammarResult check_path_grammar(const std::string& raw_path, std::string* clean_path);

// Step 2: Lexical normalization and dotfile check (§10 (d), (e))
// Returns normalized relative path (without leading slash) or false if lexical escape or dot component.
bool normalize_lexical_path(const std::string& clean_path, std::string* normalized_path, std::string* error_reason);

// Step 3: Filesystem resolution and component-wise containment check (§10 (f), (g))
PathResolveResult resolve_under_root(
    const std::string& root_dir,
    const std::string& normalized_path,
    ResolvedFile* out_file,
    std::string* error_reason);

// MIME type from file extension
std::string get_mime_type(const std::string& path);

} // namespace hooh
