#pragma once
#include <string_view>
#include <vector>
#include "secure_buffer.hpp"

namespace vault {

// Zero-Copy view on a vault entry.
// Does not own memory: points directly inside the decrypted SecureBuffer.
struct EntryView {
    std::string_view url;
    std::string_view login;
    std::string_view password;
    std::string_view notes;
};

std::vector<EntryView> parse_vault(const SecureBuffer& pt);
SecureBuffer serialize_vault(const std::vector<EntryView>& entries);

} // namespace vault