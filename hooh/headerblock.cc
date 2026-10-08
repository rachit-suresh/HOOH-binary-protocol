#include "headerblock.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>

namespace hooh {

static const char* kStaticNames[kStaticTableSize + 1] = {
    "",                 // 0
    ":method",          // 1
    ":path",            // 2
    ":status",          // 3
    "host",             // 4
    "user-agent",       // 5
    "server",           // 6
    "date",             // 7
    "content-type",     // 8
    "content-length",   // 9
    "accept"            // 10
};

const char* static_header_name(uint8_t index) {
    if (index >= 1 && index <= kStaticTableSize) {
        return kStaticNames[index];
    }
    return nullptr;
}

static std::string to_lower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

uint8_t static_header_index(const std::string& name) {
    std::string lower = to_lower(name);
    for (uint8_t i = 1; i <= kStaticTableSize; ++i) {
        if (lower == kStaticNames[i]) {
            return i;
        }
    }
    return 0;
}

bool HeaderBlock::has_header(const std::string& name) const {
    std::string lower = to_lower(name);
    for (const auto& f : fields) {
        if (f.name == lower) return true;
    }
    return false;
}

std::string HeaderBlock::get_header(const std::string& name) const {
    std::string lower = to_lower(name);
    // Last wins
    for (auto it = fields.rbegin(); it != fields.rend(); ++it) {
        if (it->name == lower) {
            return it->value;
        }
    }
    return "";
}

void HeaderBlock::set_header(const std::string& name, const std::string& value) {
    std::string lower = to_lower(name);
    uint8_t idx = static_header_index(lower);
    for (auto& f : fields) {
        if (f.name == lower) {
            f.value = value;
            f.static_index = idx;
            return;
        }
    }
    fields.push_back({lower, value, idx});
}

const char* block_error_to_string(BlockError err) {
    switch (err) {
        case BlockError::Ok: return "Ok";
        case BlockError::MalformedGrammar: return "MalformedGrammar";
        case BlockError::UnknownPseudo: return "UnknownPseudo";
        case BlockError::MissingPseudo: return "MissingPseudo";
        case BlockError::DuplicatePseudo: return "DuplicatePseudo";
        case BlockError::WrongDirection: return "WrongDirection";
        case BlockError::PseudoAfterRegular: return "PseudoAfterRegular";
        case BlockError::InvalidMethod: return "InvalidMethod";
        case BlockError::InvalidPath: return "InvalidPath";
        case BlockError::InvalidStatus: return "InvalidStatus";
        case BlockError::InvalidContentLength: return "InvalidContentLength";
        default: return "UnknownBlockError";
    }
}

static bool is_valid_token(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        auto uc = static_cast<unsigned char>(c);
        if (uc <= 0x20 || uc >= 0x7F) return false;
        // Delimiters
        if (strchr("()<>@,;:\\\"/[]?={}", c) != nullptr) return false;
    }
    return true;
}

static bool parse_uint64(const std::string& s, uint64_t* out) {
    if (s.empty()) return false;
    uint64_t val = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        uint64_t digit = static_cast<uint64_t>(c - '0');
        if (val > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
            return false; // overflow
        }
        val = val * 10 + digit;
    }
    *out = val;
    return true;
}

std::variant<HeaderBlock, BlockError> decode_header_block(
    const uint8_t* data, size_t length, Direction dir) {

    HeaderBlock block;
    size_t pos = 0;

    bool seen_regular = false;
    bool seen_method = false;
    bool seen_path = false;
    bool seen_status = false;

    while (pos < length) {
        uint8_t name_byte = data[pos++];
        std::string name;
        uint8_t s_idx = 0;

        if (name_byte == HDR_LITERAL) {
            if (pos >= length) {
                return BlockError::MalformedGrammar;
            }
            uint8_t name_len = data[pos++];
            if (name_len == 0) {
                return BlockError::MalformedGrammar; // zero-length literal name
            }
            if (pos + name_len > length) {
                return BlockError::MalformedGrammar; // overrun
            }
            name = std::string(reinterpret_cast<const char*>(data + pos), name_len);
            pos += name_len;

            // Treat literal name matching static table as that static name
            std::string lower_name = to_lower(name);
            s_idx = static_header_index(lower_name);
            if (s_idx != 0) {
                name = kStaticNames[s_idx];
            } else {
                name = lower_name;
            }
        } else if (name_byte <= kStaticTableSize) {
            s_idx = name_byte;
            name = kStaticNames[s_idx];
        } else {
            // Name 0x0B–0xFF = malformed (closed static index vocabulary)
            return BlockError::MalformedGrammar;
        }

        // Value length [2B LE]
        if (pos + 2 > length) {
            return BlockError::MalformedGrammar;
        }
        uint16_t value_len = load_le16(data + pos);
        pos += 2;

        if (pos + value_len > length) {
            return BlockError::MalformedGrammar;
        }
        std::string value(reinterpret_cast<const char*>(data + pos), value_len);
        pos += value_len;

        bool is_pseudo = (!name.empty() && name[0] == ':');

        if (is_pseudo) {
            if (seen_regular) {
                return BlockError::PseudoAfterRegular;
            }
            if (name == ":method") {
                if (dir != Direction::Request) return BlockError::WrongDirection;
                if (seen_method) return BlockError::DuplicatePseudo;
                if (!is_valid_token(value)) return BlockError::InvalidMethod;
                seen_method = true;
                block.method = value;
            } else if (name == ":path") {
                if (dir != Direction::Request) return BlockError::WrongDirection;
                if (seen_path) return BlockError::DuplicatePseudo;
                if (value.empty() || value[0] != '/' || value.find('\0') != std::string::npos) {
                    return BlockError::InvalidPath;
                }
                seen_path = true;
                block.path = value;
            } else if (name == ":status") {
                if (dir != Direction::Response) return BlockError::WrongDirection;
                if (seen_status) return BlockError::DuplicatePseudo;
                if (value.size() != 3 || !std::isdigit(static_cast<unsigned char>(value[0])) ||
                    !std::isdigit(static_cast<unsigned char>(value[1])) ||
                    !std::isdigit(static_cast<unsigned char>(value[2]))) {
                    return BlockError::InvalidStatus;
                }
                seen_status = true;
                block.status = value;
            } else {
                // Unknown pseudo header beginning with ':' is malformed
                return BlockError::UnknownPseudo;
            }
        } else {
            // Regular header
            seen_regular = true;
            if (s_idx == HDR_CONTENT_LENGTH) {
                uint64_t cl_val = 0;
                if (!parse_uint64(value, &cl_val)) {
                    return BlockError::InvalidContentLength;
                }
                block.has_content_length = true;
                block.content_length = cl_val;
            }

            // Unknown literal not beginning with ':' must be ignored (§9)
            // But if it is known or recognized, we record it.
            // Even if ignored per spec semantics, we can discard or store it without error.
            // Let's store regular headers for application use.
            // "Duplicate regular headers: last wins."
            bool replaced = false;
            for (auto& f : block.fields) {
                if (f.name == name) {
                    f.value = value;
                    f.static_index = s_idx;
                    replaced = true;
                    break;
                }
            }
            if (!replaced) {
                block.fields.push_back({name, value, s_idx});
            }
        }
    }

    // Verify required pseudo-headers
    if (dir == Direction::Request) {
        if (!seen_method || !seen_path) {
            return BlockError::MissingPseudo;
        }
    } else {
        if (!seen_status) {
            return BlockError::MissingPseudo;
        }
    }

    return block;
}

std::vector<uint8_t> encode_header_block(const HeaderBlock& block, Direction dir) {
    std::vector<uint8_t> out;

    auto append_field = [&](uint8_t s_idx, const std::string& name, const std::string& val) {
        if (s_idx != 0) {
            out.push_back(s_idx);
        } else {
            out.push_back(HDR_LITERAL);
            out.push_back(static_cast<uint8_t>(name.size()));
            out.insert(out.end(), name.begin(), name.end());
        }
        uint8_t vlen_bytes[2];
        store_le16(vlen_bytes, static_cast<uint16_t>(val.size()));
        out.push_back(vlen_bytes[0]);
        out.push_back(vlen_bytes[1]);
        out.insert(out.end(), val.begin(), val.end());
    };

    if (dir == Direction::Request) {
        // :method
        append_field(HDR_METHOD, ":method", block.method);
        // :path
        append_field(HDR_PATH, ":path", block.path);
    } else {
        // :status
        append_field(HDR_STATUS, ":status", block.status);
    }

    // Regular headers
    for (const auto& f : block.fields) {
        uint8_t idx = f.static_index;
        if (idx == 0) {
            idx = static_header_index(f.name);
        }
        append_field(idx, f.name, f.value);
    }

    return out;
}

} // namespace hooh
