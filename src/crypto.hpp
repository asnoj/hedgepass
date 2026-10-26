#pragma once
#include <sodium.h>
#include <cstdint>
#include <cstddef>
#include <vector>
#include "secure_buffer.hpp"

namespace vault {

// File format constraints and constants
constexpr unsigned char MAGIC[4] = {'P', 'M', 'V', '1'};
constexpr std::size_t SALT_LEN   = crypto_pwhash_SALTBYTES;
constexpr std::size_t NONCE_LEN  = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t KEY_LEN    = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
constexpr std::size_t TAG_LEN    = crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr std::size_t HEADER_LEN = 4 + SALT_LEN + 8 + 8 + NONCE_LEN;

constexpr std::uint64_t MAX_MEM = 1ULL << 30;  // 1 GiB
constexpr std::uint64_t MAX_OPS = 20;

SecureBuffer derive_key(const char* pw, std::size_t pw_len,
                        const unsigned char* salt,
                        std::uint64_t ops, std::uint64_t mem);

std::vector<unsigned char> seal(const char* pw, std::size_t pw_len,
                                const unsigned char* pt, std::size_t pt_len);

SecureBuffer open(const char* pw, std::size_t pw_len,
                  const std::vector<unsigned char>& file);

} // namespace vault