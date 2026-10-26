# 🦔 Threat Model & Security Architecture: hedgepass

`hedgepass` is a local, single-user command-line password manager. Its only secret store is one encrypted file on disk (`passwords.vault`), and its attacker model is built around what can realistically happen to that file and to the process that handles it. This document states what the design protects against, how, and, just as importantly, what it does not.

> This is a learning and portfolio project. It has not been independently audited.

---

## 1. Core principles

- **Kerckhoffs's principle.** Security relies on the entropy of the master password and the cost of Argon2id key derivation. The code, the file format and the algorithms are public.
- **No custom cryptography.** Every cryptographic operation uses peer-reviewed `libsodium` primitives (`crypto_pwhash` with Argon2id, and `crypto_aead_xchacha20poly1305_ietf`). This project only assembles them.
- **Careful handling of secrets in memory.** Keys and plaintexts are kept in `SecureBuffer`, a C++17 RAII wrapper over `sodium_malloc`: memory pages are locked with `mlock`, surrounded by guard pages, and zeroed when released. The class is move-only, so a secret is never silently copied.

---

## 2. Cryptographic architecture

### Key derivation (KDF)

- **Algorithm:** Argon2id (`crypto_pwhash_ALG_ARGON2ID13`).
- **Salt:** 16 random bytes from `randombytes_buf`, generated for each vault. It defeats precomputed tables and ensures two vaults with the same password get different keys.
- **Default cost:** `crypto_pwhash_OPSLIMIT_MODERATE` and `crypto_pwhash_MEMLIMIT_MODERATE`.
- **Anti-DoS validation.** The KDF parameters are stored in the header, which is read *before* it can be authenticated. They are therefore range-checked before any memory is allocated:
  - `ops` must be between 1 and 20.
  - `mem` must be between 8192 bytes and 1 GiB (`1ULL << 30`).

### Authenticated encryption (AEAD)

- **Algorithm:** XChaCha20-Poly1305 (`crypto_aead_xchacha20poly1305_ietf`).
- **Nonce:** 24 random bytes, freshly generated for every encryption (`NONCE_LEN = 24`). At this size, random generation makes accidental reuse negligible.
- **Associated data:** the entire 60-byte header (4-byte magic `PMV1` + 16-byte salt + 8-byte `OpsLimit` + 8-byte `MemLimit` + 24-byte nonce) is authenticated alongside the ciphertext.
- **Integrity:** changing any header byte or any ciphertext bit makes verification of the 16-byte Poly1305 tag fail, and decryption aborts.
- **Uniform failure message.** A wrong password and a corrupted or tampered file produce the same generic error (`Wrong password or corrupted file`), so the program does not reveal which of the two happened.

---

## 3. Data storage and reliability

### Binary file layout (`passwords.vault`)

```text
+----------------+--------------+-----------------+-----------------+---------------+------------------------+
| Magic "PMV1"   | Salt         | OpsLimit        | MemLimit        | Nonce         | Ciphertext + MAC tag   |
| 4 bytes        | 16 bytes     | 8 bytes (LE)    | 8 bytes (LE)    | 24 bytes      | payload + 16 bytes     |
+----------------+--------------+-----------------+-----------------+---------------+------------------------+
```

The magic and version field allow the format to evolve without breaking existing vaults.

### Atomic disk writes (write-then-replace)

To avoid a corrupted vault after a crash, a power loss or an interrupted write:

1. The data is serialized into a locked `SecureBuffer` and encrypted.
2. A temporary file (`passwords.vault.tmp`) is created with restrictive permissions (`umask(0077)`, resulting mode `0600`).
3. The ciphertext is written with POSIX `write()`.
4. The kernel buffers are flushed to storage with `fsync(fd)`.
5. The temporary file is atomically renamed to `passwords.vault` with `std::filesystem::rename()`.

At every point, either the old vault or the new vault exists in full on disk, never a half-written one.

---

## 4. In scope and out of scope

### In scope (the design aims to protect against)

- **Theft of the vault file.** Reading `passwords.vault` without the master password (stolen disk, leaked backup). An attacker has to brute-force the password through Argon2id, whose memory cost limits GPU and ASIC parallelism.
- **Tampering with the vault file.** Modifying the KDF limits, the nonce or the ciphertext is detected by Poly1305 verification.
- **Swapping of secrets to disk.** Data held in `SecureBuffer` is locked in RAM with `mlock()`, so it is not paged out to swap (see the limits in section 5).
- **Memory-safety bugs in the file parser.** The binary parser is tested with AddressSanitizer, UndefinedBehaviorSanitizer and an LLVM `libFuzzer` target, which target out-of-bounds reads, integer overflows and heap corruption.
- **Secrets lingering after use.** Releasing a `SecureBuffer` zeroes its memory through libsodium, and RAII ensures this also happens when an exception is thrown.
- **Loss of the vault from an interrupted save.** Covered by the atomic write pattern above.

### Out of scope (known limits)

- **Privileged attacker or malware on the same account.** An attacker with root privileges, or with `ptrace` access to the running process, can read process memory or dump RAM.
- **Transient memory inside libsodium.** The scratch memory that `crypto_pwhash` allocates during Argon2id is managed by libsodium internally and is not under `SecureBuffer`'s control, so it should not be assumed to carry the same locking and zeroing guarantees.
- **Clipboard interception.** A password copied with `wl-copy` or `xclip` is readable by other applications in the same graphical session. The 20-second auto-clear shortens the exposure window but does not remove it, and X11 offers little isolation between clients.
- **Keyloggers and input hooks.** Hardware keyloggers, or software that hooks keyboard input at the OS or display-server level, can capture the master password as it is typed. `hedgepass` cannot defend against this.
- **Weak master passwords.** Argon2id makes each guess expensive, but it cannot rescue a password that is easy to guess.

---

## 5. Additional limitations to be aware of

- **`mlock` limits.** Locking memory is subject to the per-process OS limit (ulimit -l, RLIMIT_MEMLOCK). If this limit is exceeded, sodium_malloc fails closed by returning NULL, causing SecureBuffer to throw an exception rather than silently operating in un-locked RAM.
- **Hibernation.** Suspend-to-disk writes all of RAM to storage, including locked pages. Full-disk encryption of the swap or hibernation partition is the appropriate mitigation, and it lies outside `hedgepass`.
- **Core dumps.** If the process crashes, a core dump could contain secrets unless dumps are disabled or restricted on the system.
- **Not audited.** The design follows established practice, but it has not been reviewed by an independent third party.
