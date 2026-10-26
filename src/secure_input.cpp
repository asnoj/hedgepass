#include "secure_input.hpp"
#include <sodium.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <stdexcept>

Secret::Secret(std::size_t cap) : buf(cap) {}

const char* Secret::c_str() const { 
    return reinterpret_cast<const char*>(buf.data()); 
}

EchoOff::EchoOff() {
    if (!isatty(STDIN_FILENO)) return;
    
    if (tcgetattr(STDIN_FILENO, &old_) != 0)
        throw std::runtime_error("tcgetattr failed");
    
    termios t = old_;
    t.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) != 0)
        throw std::runtime_error("tcsetattr failed");
    
    active_ = true;
    instance_ = this;

    struct sigaction sa{};
    sa.sa_handler = &EchoOff::sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGINT, &sa, &old_sigint_);
}

EchoOff::~EchoOff() {
    restore();
}

void EchoOff::restore() {
    if (active_) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_);
        active_ = false;
        sigaction(SIGINT, &old_sigint_, nullptr);
        instance_ = nullptr;
    }
}

void EchoOff::sigint_handler(int /*signum*/) {
    if (instance_) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &instance_->old_);
        const char newline[] = "\n";
        auto ignore = write(STDERR_FILENO, newline, 1);
        (void)ignore;
    }
    raise(SIGINT);
}

Secret read_secret(const char* prompt, std::size_t max_len) {
    Secret s(max_len + 1);
    std::fputs(prompt, stderr);
    std::fflush(stderr);
    
    {
        EchoOff guard;
        for (;;) {
            char c = 0;
            ssize_t n = read(STDIN_FILENO, &c, 1);
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("read failed");
            }
            if (n == 0 || c == '\n') break;
            
            if (s.len >= max_len) {
                sodium_memzero(&c, 1);
                throw std::runtime_error("secret too long");
            }
            s.buf.data()[s.len++] = static_cast<unsigned char>(c);
            sodium_memzero(&c, 1);
        }
    }
    
    if (isatty(STDIN_FILENO)) std::fputc('\n', stderr);
    return s;
}