#pragma once
#include <string_view>

namespace vault {

// Copie le texte dans le presse-papiers systeme (Wayland ou X11)
void clipboard_set(std::string_view text);

// Fork un process en arriere-plan qui effacera le presse-papiers apres X secondes
void clipboard_clear_delayed(int delay_seconds);

} // namespace vault