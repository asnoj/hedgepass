#include "crypto.hpp"
#include <cstring>
#include <stdexcept>

namespace {
    // Internal helper functions (anonymous namespace hides them from other files)
    void put_u64(unsigned char* p, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) p[i] = static_cast<unsigned char>(v >> (8 * i));
    }
    
    std::uint64_t get_u64(const unsigned char* p) {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
        return v;
    }
}

namespace vault {

SecureBuffer derive_key(const char* pw, std::size_t pw_len,
                        const unsigned char* salt,
                        std::uint64_t ops, std::uint64_t mem) {
    SecureBuffer key(KEY_LEN);
    if (crypto_pwhash(key.data(), key.size(), pw, pw_len, salt, ops, mem,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Argon2id: out of memory");
    }
    return key;
}

std::vector<unsigned char> seal(const char* pw, std::size_t pw_len,
                                const unsigned char* pt, std::size_t pt_len) {
    const std::uint64_t ops = crypto_pwhash_OPSLIMIT_MODERATE;
    const std::uint64_t mem = crypto_pwhash_MEMLIMIT_MODERATE;

    std::vector<unsigned char> out(HEADER_LEN + pt_len + TAG_LEN);
    unsigned char* p = out.data();
    
    std::memcpy(p, MAGIC, 4);                          p += 4;
    randombytes_buf(p, SALT_LEN);
    unsigned char* salt = p;                           p += SALT_LEN;
    put_u64(p, ops);                                   p += 8;
    put_u64(p, mem);                                   p += 8;
    
    randombytes_buf(p, NONCE_LEN);
    unsigned char* nonce = p;

    SecureBuffer key = derive_key(pw, pw_len, salt, ops, mem);

    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data() + HEADER_LEN, &clen, pt, pt_len,
        out.data(), HEADER_LEN, nullptr, nonce, key.data());
        
    out.resize(HEADER_LEN + clen);
    return out;
}

SecureBuffer open(const char* pw, std::size_t pw_len,
                  const std::vector<unsigned char>& file) {
    if (file.size() < HEADER_LEN + TAG_LEN || std::memcmp(file.data(), MAGIC, 4) != 0)
        throw std::runtime_error("Invalid vault file");

    const unsigned char* salt  = file.data() + 4;
    const std::uint64_t  ops   = get_u64(salt + SALT_LEN);
    const std::uint64_t  mem   = get_u64(salt + SALT_LEN + 8);
    const unsigned char* nonce = salt + SALT_LEN + 16;

    if (ops < 1 || ops > MAX_OPS || mem < 8192 || mem > MAX_MEM)
        throw std::runtime_error("Unsafe KDF parameters");

    SecureBuffer key = derive_key(pw, pw_len, salt, ops, mem);

    const std::size_t clen = file.size() - HEADER_LEN;
    SecureBuffer pt(clen - TAG_LEN);
    unsigned long long plen = 0;
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &plen, nullptr,
            file.data() + HEADER_LEN, clen,
            file.data(), HEADER_LEN, nonce, key.data()) != 0) {
        throw std::runtime_error("Wrong password or corrupted file");
    }
    return pt;
}

} // namespace vault