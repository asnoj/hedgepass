#include "database.hpp"
#include <cstdint>
#include <stdexcept>
#include <cstring>

namespace {

    // --- READING UTILITIES (Deserialization) ---
    std::uint32_t read_u32(const unsigned char*& p, const unsigned char* end) {
        if (end - p < 4) throw std::runtime_error("Truncated file (reading u32)");
        std::uint32_t v = static_cast<std::uint32_t>(p[0]) | 
                         (static_cast<std::uint32_t>(p[1]) << 8) |
                         (static_cast<std::uint32_t>(p[2]) << 16) |
                         (static_cast<std::uint32_t>(p[3]) << 24);
        p += 4;
        return v;
    }

    std::uint16_t read_u16(const unsigned char*& p, const unsigned char* end) {
        if (end - p < 2) throw std::runtime_error("Truncated file (reading u16)");
        std::uint16_t v = static_cast<std::uint16_t>(p[0]) | 
                         (static_cast<std::uint16_t>(p[1]) << 8);
        p += 2;
        return v;
    }

    std::string_view read_str(const unsigned char*& p, const unsigned char* end, std::uint16_t len) {
        if (end - p < len) throw std::runtime_error("Truncated file (reading string)");
        std::string_view s(reinterpret_cast<const char*>(p), len);
        p += len;
        return s;
    }

    // --- WRITING UTILITIES (Serialization) ---
    void write_u32(unsigned char*& p, std::uint32_t v) {
        p[0] = static_cast<unsigned char>(v);
        p[1] = static_cast<unsigned char>(v >> 8);
        p[2] = static_cast<unsigned char>(v >> 16);
        p[3] = static_cast<unsigned char>(v >> 24);
        p += 4;
    }

    void write_u16(unsigned char*& p, std::uint16_t v) {
        p[0] = static_cast<unsigned char>(v);
        p[1] = static_cast<unsigned char>(v >> 8);
        p += 2;
    }

    void write_str(unsigned char*& p, std::string_view s) {
        if (!s.empty()) {
            std::memcpy(p, s.data(), s.size());
            p += s.size();
        }
    }

} // anonymous namespace

namespace vault {

std::vector<EntryView> parse_vault(const SecureBuffer& pt) {
    std::vector<EntryView> entries;
    const unsigned char* p = pt.data();
    const unsigned char* end = p + pt.size();

    if (p == end) return entries; // Empty vault

    std::uint32_t count = read_u32(p, end);
    for (std::uint32_t i = 0; i < count; ++i) {
        EntryView entry;
        entry.url      = read_str(p, end, read_u16(p, end));
        entry.login    = read_str(p, end, read_u16(p, end));
        entry.password = read_str(p, end, read_u16(p, end));
        entry.notes    = read_str(p, end, read_u16(p, end));
        entries.push_back(entry);
    }
    return entries;
}

SecureBuffer serialize_vault(const std::vector<EntryView>& entries) {
    // 1. Security check: avoid 16-bit integer overflow
    for (const auto& e : entries) {
        if (e.url.size() > 0xFFFF || e.login.size() > 0xFFFF || 
            e.password.size() > 0xFFFF || e.notes.size() > 0xFFFF) {
            throw std::runtime_error("Field too large for 16-bit length");
        }
    }

    // 2. Calculate exactly how many bytes we need
    std::size_t total_size = 4; // 4 bytes for total entries count
    for (const auto& e : entries) {
        total_size += 2 + e.url.size();
        total_size += 2 + e.login.size();
        total_size += 2 + e.password.size();
        total_size += 2 + e.notes.size();
    }

    // 3. Allocate memory block
    SecureBuffer buf(total_size);
    unsigned char* p = buf.data();

    // 4. Write sequentially
    write_u32(p, static_cast<std::uint32_t>(entries.size()));
    for (const auto& e : entries) {
        write_u16(p, static_cast<std::uint16_t>(e.url.size()));
        write_str(p, e.url);
        
        write_u16(p, static_cast<std::uint16_t>(e.login.size()));
        write_str(p, e.login);
        
        write_u16(p, static_cast<std::uint16_t>(e.password.size()));
        write_str(p, e.password);
        
        write_u16(p, static_cast<std::uint16_t>(e.notes.size()));
        write_str(p, e.notes);
    }

    return buf;
}

} // namespace vault