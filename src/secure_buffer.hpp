#pragma once
#include <cstddef>

// Buffer for secrets: locked memory (no swap), guard pages,
// zeroed on destruction. Non-copyable, movable.
class SecureBuffer {
public:
    explicit SecureBuffer(std::size_t size);
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& o) noexcept;
    SecureBuffer& operator=(SecureBuffer&& o) noexcept;

    unsigned char*       data()       noexcept;
    const unsigned char* data() const noexcept;
    std::size_t          size() const noexcept;

private:
    void release() noexcept;
    
    unsigned char* data_ = nullptr;
    std::size_t    size_ = 0;
};