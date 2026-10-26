#include "file_io.hpp"
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

namespace vault {

bool file_exists(const std::string& filepath) {
    return std::filesystem::exists(filepath);
}

std::vector<unsigned char> read_file(const std::string& filepath) {
    // Open at the end (ate) in binary mode to get the size easily
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file for reading: " + filepath);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (size > 0) {
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            throw std::runtime_error("Error while reading file: " + filepath);
        }
    }
    return buffer;
}

void write_file_atomic(const std::string& filepath, const std::vector<unsigned char>& data) {
    std::string tmp_path = filepath + ".tmp";

    // 1. Temporarily restrict umask so the new file is created with 0600 permissions
    // 0077 means: deny read/write/execute for group and others.
    mode_t old_mask = umask(0077);

    // 2. Write to the temporary file
    // We use POSIX open/write/fsync to guarantee data hits the disk before rename
    int fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    
    // Restore the old umask immediately after creation
    umask(old_mask);

    if (fd < 0) {
        throw std::runtime_error("Cannot create temp file: " + tmp_path);
    }

    // Write all data
    const unsigned char* ptr = data.data();
    std::size_t left = data.size();
    while (left > 0) {
        ssize_t written = write(fd, ptr, left);
        if (written < 0) {
            close(fd);
            std::filesystem::remove(tmp_path);
            throw std::runtime_error("Error writing to temp file");
        }
        ptr += written;
        left -= written;
    }

    // 3. Force OS to flush buffers to physical disk
    if (fsync(fd) < 0) {
        close(fd);
        std::filesystem::remove(tmp_path);
        throw std::runtime_error("Error syncing temp file to disk");
    }
    close(fd);

    // 4. Atomic rename
    std::error_code ec;
    std::filesystem::rename(tmp_path, filepath, ec);
    if (ec) {
        std::filesystem::remove(tmp_path);
        throw std::runtime_error("Atomic rename failed: " + ec.message());
    }
}

} // namespace vault