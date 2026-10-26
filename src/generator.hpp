#pragma once
#include <string>
#include <cstddef>

namespace vault {

// Generates a cryptographically secure random password.
// Default length is 20 characters.
std::string generate_password(std::size_t length = 20);

} // namespace vault