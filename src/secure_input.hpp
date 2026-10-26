#pragma once
#include <cstddef>
#include <termios.h>
#include <csignal>
#include "secure_buffer.hpp"

// A secret read from keyboard: length + protected buffer (NUL terminated)
struct Secret {
    SecureBuffer buf;
    std::size_t  len = 0;
    
    explicit Secret(std::size_t cap);
    const char* c_str() const;
};

// RAII: disables terminal echo, restores it on destruction or SIGINT
class EchoOff {
public:
    EchoOff();
    ~EchoOff();

    EchoOff(const EchoOff&) = delete;
    EchoOff& operator=(const EchoOff&) = delete;

private:
    void restore();
    static void sigint_handler(int signum);

    termios old_{};
    struct sigaction old_sigint_{};
    bool active_ = false;
    
    // C++17 inline static variable
    inline static EchoOff* instance_ = nullptr; 
};

Secret read_secret(const char* prompt, std::size_t max_len = 256);