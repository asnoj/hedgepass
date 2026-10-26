#include <iostream>
#include <cassert>
#include <cstring>
#include "crypto.hpp"
#include "database.hpp"
#include "secure_buffer.hpp"

// Simple unit testing framework (zero dependency, 100% 42-style)
int tests_passed = 0;
int tests_failed = 0;

#define RUN_TEST(test_func) \
    do { \
        std::cout << "[RUN] " << #test_func << "... "; \
        try { \
            test_func(); \
            std::cout << "OK 🟢\n"; \
            tests_passed++; \
        } catch (const std::exception& e) { \
            std::cout << "FAIL 🔴 (" << e.what() << ")\n"; \
            tests_failed++; \
        } \
    } while(0)

// Test 1: Basic encryption and decryption roundtrip
void test_roundtrip() {
    const char* pw = "correct-horse-battery-staple";
    const char* msg = "test-secret-data-123";

    auto sealed = vault::seal(pw, std::strlen(pw), 
                              reinterpret_cast<const unsigned char*>(msg), std::strlen(msg));
    
    auto pt = vault::open(pw, std::strlen(pw), sealed);

    assert(pt.size() == std::strlen(msg));
    assert(std::memcmp(pt.data(), msg, pt.size()) == 0);
}

// Test 2: Wrong password must be rejected
void test_wrong_password() {
    const char* pw = "good-password";
    const char* msg = "secret";

    auto sealed = vault::seal(pw, std::strlen(pw), 
                              reinterpret_cast<const unsigned char*>(msg), std::strlen(msg));
    
    bool caught = false;
    try {
        vault::open("bad-password", 12, sealed);
    } catch (const std::runtime_error&) {
        caught = true;
    }
    assert(caught);
}

// Test 3: Tampering with ciphertext must invalidate the Poly1305 tag
void test_tamper_detection() {
    const char* pw = "password123";
    const char* msg = "sensitive data";

    auto sealed = vault::seal(pw, std::strlen(pw), 
                              reinterpret_cast<const unsigned char*>(msg), std::strlen(msg));
    
    // Corrupt a byte in the ciphertext part
    sealed[vault::HEADER_LEN + 2] ^= 0x42;

    bool caught = false;
    try {
        vault::open(pw, std::strlen(pw), sealed);
    } catch (const std::runtime_error&) {
        caught = true;
    }
    assert(caught);
}

// Test 4: Hostile KDF parameters (Anti-DoS check)
void test_hostile_kdf() {
    const char* pw = "password123";
    const char* msg = "data";

    auto sealed = vault::seal(pw, std::strlen(pw), 
                              reinterpret_cast<const unsigned char*>(msg), std::strlen(msg));
    
    // Manually inject an unsafe memory limit into the header (e.g., 500 GiB)
    std::uint64_t hostile_mem = 500ULL << 30; 
    unsigned char* p = sealed.data() + 4 + vault::SALT_LEN + 8; // pointer to memlimit
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<unsigned char>(hostile_mem >> (8 * i));
    }

    bool caught = false;
    try {
        vault::open(pw, std::strlen(pw), sealed);
    } catch (const std::runtime_error& e) {
        std::string err = e.what();
        if (err.find("Unsafe KDF parameters") != std::string::npos) {
            caught = true;
        }
    }
    assert(caught);
}

// Test 5: Database serialization and zero-copy parsing
void test_database_serialization() {
    std::vector<vault::EntryView> entries;
    std::string url = "https://github.com";
    std::string login = "asnoj";
    std::string pass = "super-secret-pass";
    std::string notes = "hedgemon creator";

    vault::EntryView entry;
    entry.url = url;
    entry.login = login;
    entry.password = pass;
    entry.notes = notes;
    entries.push_back(entry);

    SecureBuffer raw = vault::serialize_vault(entries);
    auto parsed = vault::parse_vault(raw);

    assert(parsed.size() == 1);
    assert(parsed[0].url == url);
    assert(parsed[0].login == login);
    assert(parsed[0].password == pass);
    assert(parsed[0].notes == notes);
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "fatal: sodium_init failed\n";
        return 1;
    }

    std::cout << "🦔 running pwvault test suite...\n\n";

    RUN_TEST(test_roundtrip);
    RUN_TEST(test_wrong_password);
    RUN_TEST(test_tamper_detection);
    RUN_TEST(test_hostile_kdf);
    RUN_TEST(test_database_serialization);

    std::cout << "\n-------------------\n";
    std::cout << "Tests passed: " << tests_passed << "\n";
    std::cout << "Tests failed: " << tests_failed << "\n";

    return (tests_failed > 0) ? 1 : 0;
}