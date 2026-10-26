#include "secure_buffer.hpp"
#include <sodium.h>
#include <new>
#include <utility>

SecureBuffer::SecureBuffer(std::size_t size) : size_(size) {
    if (size_ == 0) return;
    data_ = static_cast<unsigned char*>(sodium_malloc(size_));
    if (!data_) throw std::bad_alloc();
    sodium_memzero(data_, size_);
}

SecureBuffer::~SecureBuffer() { 
    release(); 
}

SecureBuffer::SecureBuffer(SecureBuffer&& o) noexcept
    : data_(std::exchange(o.data_, nullptr)), size_(std::exchange(o.size_, 0)) {}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& o) noexcept {
    if (this != &o) {
        release();
        data_ = std::exchange(o.data_, nullptr);
        size_ = std::exchange(o.size_, 0);
    }
    return *this;
}

unsigned char* SecureBuffer::data() noexcept { return data_; }
const unsigned char* SecureBuffer::data() const noexcept { return data_; }
std::size_t SecureBuffer::size() const noexcept { return size_; }

void SecureBuffer::release() noexcept {
    if (data_) sodium_free(data_); // zeroes then frees
    data_ = nullptr;
    size_ = 0;
}