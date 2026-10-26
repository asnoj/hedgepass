#include <cstdint>
#include <cstddef>
#include <cstring> // <-- MISSING INCLUDE FIXED HERE
#include <stdexcept>
#include <sodium.h>
#include "database.hpp"
#include "secure_buffer.hpp"
#include "crypto.hpp"

// Initialize libsodium once before fuzzing iterations start
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;
    if (sodium_init() < 0) {
        return 0;
    }
    return 0;
}

// LLVM libFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    if (size == 0) return 0;

    // 1. High-Speed Fuzzing: Stress-test the database binary parser directly.
    // We treat 'data' as if it were a decrypted SecureBuffer payload.
    // This bypasses Argon2id and runs at 100,000+ executions per second.
    try {
        // We create a temporary SecureBuffer from raw fuzz bytes
        SecureBuffer raw_payload(size);
        std::memcpy(raw_payload.data(), data, size);

        // Feed arbitrary garbage bytes into our binary parser
        auto entries = vault::parse_vault(raw_payload);
        (void)entries;
    } catch (const std::exception&) {
        // Expected behavior: gracefully catch parser validation errors
    }

    // 2. Format Validation Fuzzing: Check header checks on vault::open
    // (Only executed on small payloads to avoid slow Argon2id hash rate)
    if (size < vault::HEADER_LEN + vault::TAG_LEN) {
        try {
            std::vector<unsigned char> corrupt_file(data, data + size);
            vault::open("dummy_password", 14, corrupt_file);
        } catch (const std::exception&) {
            // Expected behavior: gracefully reject invalid vault files
        }
    }

    return 0; // Return 0 to tell libFuzzer to keep mutating
}