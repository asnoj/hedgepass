#include "generator.hpp"
#include <cstdint>
#include <sodium.h>

namespace vault {

std::string generate_password(std::size_t length) {
    // We include letters, numbers, and safe special characters
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789"
                           "-_!@#$%^&*()";
    
    const std::size_t charset_size = sizeof(charset) - 1; // -1 to ignore the trailing \0
    
    std::string password;
    password.reserve(length);
    
    for (std::size_t i = 0; i < length; ++i) {
        // randombytes_uniform avoids the modulo bias natively
        std::uint32_t index = randombytes_uniform(charset_size);
        password.push_back(charset[index]);
    }
    
    return password;
}

} // namespace vault