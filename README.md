<h1 align="center">🦔 hedgepass 🦔</h1>

<p align="center">
A minimal, spiky command-line password manager written in C++17 on top of libsodium.<br>
Memory-hygienic by design, built to be small enough to read in one sitting.
</p>

```text
  .::::::::..                                                                                            ..::::::::.
 :::::::::::::                                                                                          :::::::::::::
:::::::::::' .\                                                                                       /. `:::::::::::
`::::::::::_,__o                                                                                     o__,_::::::::::'
```

> **Status:** v1, a learning and portfolio project. It has not been independently audited. Read [`THREAT_MODEL.md`](THREAT_MODEL.md) before trusting it with anything that matters.

---

## What is this?

`hedgepass` keeps your credentials in a single encrypted vault file. The only runtime dependency is [libsodium](https://libsodium.org); everything else is C++17 and POSIX system calls.

The goal of the project is not to out-feature existing managers, but to show how the security-critical parts can be assembled carefully from well-reviewed primitives: no home-made cryptography, explicit handling of secrets in memory, atomic file writes, and a fuzzed parser for untrusted input.

## Features

- **Modern cryptography.** Argon2id key derivation (`crypto_pwhash`) and XChaCha20-Poly1305 authenticated encryption, with the whole file header authenticated as associated data.
- **Protected memory.** Secrets live in `SecureBuffer`, a RAII wrapper over `sodium_malloc`: locked pages (`mlock`), guard pages, and guaranteed zeroing on destruction. The buffer is move-only, so a secret is never silently duplicated.
- **Zero-copy parsing.** Decrypted entries are parsed as `std::string_view`s pointing directly into the locked buffer, so secrets are not copied into ordinary heap-allocated strings.
- **Atomic file I/O.** Saves follow the POSIX write-then-replace pattern (`open` → `fsync` → `rename`) under a restrictive `umask(0077)`. A crash or power loss cannot leave a half-written vault behind.
- **Terminal hygiene.** Echo is disabled for secret prompts and restored on exit, including on `SIGINT`.
- **Clipboard with auto-clear.** Wayland (`wl-copy`) and X11 (`xclip`) are supported. A detached helper process clears the clipboard after 20 seconds.
- **Unbiased password generator.** Uses `randombytes_uniform`, so there is no modulo bias.
- **Tested and fuzzed.** A dependency-free unit test runner, plus a LLVM `libFuzzer` target for the vault parser, run under AddressSanitizer and UndefinedBehaviorSanitizer.

## Building

### Prerequisites

- A C++17 compiler (developed with GCC 16.2; Clang is needed for the fuzzer)
- CMake 3.16+
- libsodium 1.0.18+
- `wl-clipboard` (Wayland) or `xclip` (X11), for clipboard support

```bash
# Arch Linux
sudo pacman -S libsodium cmake wl-clipboard

# Debian / Ubuntu
sudo apt install libsodium-dev cmake pkg-config wl-clipboard
```

### Development build (sanitizers on)

```bash
mkdir build && cd build
cmake -DSANITIZE=ON ..
make
./hedgepass_test
```

### Release build

```bash
mkdir build-rel && cd build-rel
cmake ..
make
```

### Fuzzing

```bash
mkdir build-fuzz && cd build-fuzz
CXX=clang++ cmake -DFUZZ=ON ..
make hedgepass_fuzz
./hedgepass_fuzz
```

The fuzz target feeds arbitrary bytes to the binary vault parser. On my machine it runs at roughly 9,000 executions per second with ASan and UBSan enabled.

## Usage

```bash
# Create a new encrypted vault (asks for the master password twice)
./hedgepass init

# Add an entry (URL, login, notes, password)
./hedgepass add

# List entries (metadata only; passwords are never printed)
./hedgepass list

# Copy a password to the clipboard (cleared after 20 seconds)
./hedgepass get https://github.com

# Generate a random 20-character password
./hedgepass generate
```

| Command | Description |
| --- | --- |
| `init` | Prompts for a master password twice and creates an empty vault (`passwords.vault`). |
| `add` | Asks for the entry details, decrypts the vault briefly, appends the entry, re-encrypts, and writes the file atomically. |
| `list` | Shows URL, login and notes for every entry without displaying passwords. |
| `get <url>` | Decrypts the vault, copies the matching password to the clipboard, and starts a background process that clears it after 20 seconds. |
| `generate` | Generates a 20-character password with `randombytes_uniform`. |

## Project layout

```text
src/
├── main.cpp           CLI entry point and command workflows
├── secure_buffer.cpp  RAII wrapper over sodium_malloc (mlock, guard pages, wipe on free)
├── crypto.cpp         Argon2id key derivation and XChaCha20-Poly1305 sealing/opening
├── secure_input.cpp   termios echo suppression, restored on SIGINT
├── database.cpp       Binary serialization and zero-copy std::string_view parser
├── file_io.cpp        Atomic POSIX writes (open, fsync, rename) under umask(0077)
├── generator.cpp      CSPRNG password generation without modulo bias
├── clipboard.cpp      Clipboard handling and the detached clearing process
├── tests.cpp          Unit test runner (no external framework)
└── fuzz_target.cpp    libFuzzer entry point for the vault parser
```

## Vault format

A vault file has a fixed binary header followed by the encrypted payload:

```text
+----------------+--------------+-----------------+-----------------+---------------+------------------------+
| Magic "PMV1"   | Salt         | OpsLimit        | MemLimit        | Nonce         | Ciphertext + tag       |
| 4 bytes        | 16 bytes     | 8 bytes (LE)    | 8 bytes (LE)    | 24 bytes      | payload + 16 bytes     |
+----------------+--------------+-----------------+-----------------+---------------+------------------------+
```

- The master password and the salt go through Argon2id (with the stored `OpsLimit` and `MemLimit`) to derive a 256-bit key.
- The payload is encrypted with XChaCha20-Poly1305 using a fresh random 24-byte nonce for every save.
- The **entire header** (magic, salt, KDF limits and nonce) is passed to the cipher as associated data. Changing a single header byte, for example to weaken the KDF parameters, makes authentication fail.
- The magic and version let the format evolve without breaking older files.

## Design decisions

- **Argon2id instead of a fast hash.** A fast hash lets an attacker with a stolen vault test billions of passwords per second on a GPU. Argon2id is deliberately slow and memory-hungry.
- **An AEAD cipher.** XChaCha20-Poly1305 provides confidentiality and integrity at once, so a tampered file is rejected instead of silently decrypting to garbage. Its 24-byte nonce can be generated randomly without worrying about collisions.
- **No custom cryptography.** All primitives come from libsodium; this project only assembles them.
- **Untrusted headers are bounded.** The KDF parameters are read from the file before authentication, so they are range-checked (`MAX_MEM` = 1 GiB, `MAX_OPS` = 20) to stop a crafted file from exhausting memory.
- **One error for two failures.** A wrong password and a corrupted file produce the same message, so the program gives an attacker no extra information.
- **Open design.** Following Kerckhoffs's principle, security rests on the master password's entropy and the Argon2id cost parameters, not on the code being secret.

## Threat model (summary)

**Designed to resist**

- Theft or leakage of the vault file (disk theft, leaked backup): the attacker must brute-force the master password through Argon2id.
- Modification of the vault file: any change, including to the header, is detected.
- Malformed or malicious vault files: parsing is bounded and fuzzed.
- Data loss from crashes or power failures during a save.

**Out of scope**

- An attacker with root access or debugger access to the running process.
- Keyloggers, screen capture, or other malware running as you.
- Other programs reading the clipboard during the 20-second window.
- A weak master password.

The full reasoning, assumptions and known OS-level limitations are in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Ideas for later

- Master password change with re-encryption
- Breach checking via Have I Been Pwned using k-anonymity
- Weak and reused password detection
- TOTP code generation

## Disclaimer

This is a personal project built to learn and demonstrate secure C++ and applied cryptography. It has not been audited. For anything critical, use an established, audited password manager.d binary header followed by the encrypted payload:
