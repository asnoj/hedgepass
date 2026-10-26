#include "clipboard.hpp"
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <string>

namespace vault {

void clipboard_set(std::string_view text) {
    bool is_wayland = (std::getenv("WAYLAND_DISPLAY") != nullptr);
    const char* cmd = is_wayland ? "wl-copy" : "xclip -selection clipboard";

    FILE* f = popen(cmd, "w");
    if (f) {
        std::fwrite(text.data(), 1, text.size(), f);
        pclose(f);
    }
}

void clipboard_clear_delayed(int delay_seconds) {
    // Capture environment variables before forking, so the background process 
    // knows which graphical display to talk to.
    const char* wayland_disp = std::getenv("WAYLAND_DISPLAY");
    const char* xdg_runtime  = std::getenv("XDG_RUNTIME_DIR");
    const char* display      = std::getenv("DISPLAY");

    pid_t pid = fork();
    if (pid < 0) return; // Fork failed
    
    if (pid == 0) {
        // --- CHILD PROCESS ---
        
        // Restore necessary environment variables in the detached context
        if (wayland_disp) setenv("WAYLAND_DISPLAY", wayland_disp, 1);
        if (xdg_runtime)  setenv("XDG_RUNTIME_DIR", xdg_runtime, 1);
        if (display)      setenv("DISPLAY", display, 1);

        setsid();
        
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        
        sleep(delay_seconds);
        
        // Build the clear command with proper context
        bool is_wayland = (wayland_disp != nullptr);
        std::string cmd = is_wayland ? "wl-copy --clear" : "xclip -selection clipboard -i /dev/null";
        
        int res = std::system(cmd.c_str());
        (void)res;
        
        _exit(0);
    }
    // --- PARENT PROCESS ---
    // Returns immediately, leaving the child running in the background
}

} // namespace vault
