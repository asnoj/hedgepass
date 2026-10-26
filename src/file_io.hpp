#pragma once
#include <vector>
#include <string>

namespace vault {

// Reads an entire file into a byte vector.
// Throws if the file does not exist or cannot be read.
std::vector<unsigned char> read_file(const std::string& filepath);

// Writes data atomically to filepath.
// Ensures permissions are restricted (0600 equivalent) via process umask.
void write_file_atomic(const std::string& filepath, const std::vector<unsigned char>& data);

// Checks if a file exists.
bool file_exists(const std::string& filepath);

} // namespace vault