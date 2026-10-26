#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include "crypto.hpp"
#include "secure_input.hpp"
#include "database.hpp"
#include "file_io.hpp"
#include "generator.hpp"
#include "clipboard.hpp"

using namespace vault;

const std::string VAULT_FILE = "passwords.vault";

void print_usage()
{
    std::cerr << "🦔 hedgepass - the spiky password vault\n"
              << "usage:\n"
              << "  hedgepass init       : initialize a new empty vault\n"
              << "  hedgepass add        : add a new entry\n"
              << "  hedgepass list       : list existing entries\n"
              << "  hedgepass get <url>  : copy password to clipboard\n"
              << "  hedgepass generate   : generate a secure password\n";
}

// helper to read non-secret text (url, login)
std::string read_clear(const char* prompt) {
    std::string res;
    std::cerr << prompt;
    std::getline(std::cin, res);
    return res;
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "fatal error: sodium_init() failed\n";
        return 1;
    }

    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string cmd = argv[1];

    try {
        if (cmd == "init") {
            if (file_exists(VAULT_FILE)) {
                std::cerr << "error: " << VAULT_FILE << " already exists. we do not overwrite >;[\n";
                return 1;
            }

            Secret master1 = read_secret("new master password: ");
            Secret master2 = read_secret("confirm: ");

            if (master1.len != master2.len || 
                sodium_memcmp(master1.buf.data(), master2.buf.data(), master1.len) != 0) {
                std::cerr << "error: passwords do not match.\n";
                return 1;
            }

            std::vector<EntryView> empty_entries;
            SecureBuffer raw_vault = serialize_vault(empty_entries);
            auto sealed = seal(master1.c_str(), master1.len, raw_vault.data(), raw_vault.size());
            write_file_atomic(VAULT_FILE, sealed);
            
            std::cout << "vault initialized successfully c:\n";
        } 
        else if (cmd == "list") {
            Secret master = read_secret("master password: ");
            
            auto sealed = read_file(VAULT_FILE);
            SecureBuffer raw_vault = open(master.c_str(), master.len, sealed);
            auto entries = parse_vault(raw_vault);
            
            std::cout << "\n--- 🦔 vault content (" << entries.size() << " entries) ---\n";
            for (const auto& e : entries) {
                std::cout << "URL   : " << e.url << "\n"
                          << "Login : " << e.login << "\n"
                          << "Notes : " << e.notes << "\n"
                          << "-----------------------\n";
            }
        }
        else if (cmd == "add") {
            std::string url   = read_clear("URL: ");
            std::string login = read_clear("Login: ");
            std::string notes = read_clear("Notes: ");
            Secret new_pass   = read_secret("Password: ");
            Secret master     = read_secret("Master password to confirm: ");

            auto sealed = read_file(VAULT_FILE);
            SecureBuffer raw_vault = open(master.c_str(), master.len, sealed);
            auto entries = parse_vault(raw_vault);

            EntryView new_entry;
            new_entry.url      = url;
            new_entry.login    = login;
            new_entry.notes    = notes;
            new_entry.password = std::string_view(new_pass.c_str(), new_pass.len);

            entries.push_back(new_entry);

            SecureBuffer new_raw = serialize_vault(entries);
            auto new_sealed = seal(master.c_str(), master.len, new_raw.data(), new_raw.size());
            write_file_atomic(VAULT_FILE, new_sealed);

            std::cout << "entry added successfully >;]\n";
        }
        else if (cmd == "get") {
            if (argc != 3) {
                std::cerr << "usage: pwvault get <url>\n";
                return 1;
            }
            std::string target = argv[2];
            
            Secret master = read_secret("master password: ");
            auto sealed = read_file(VAULT_FILE);
            SecureBuffer raw_vault = open(master.c_str(), master.len, sealed);
            auto entries = parse_vault(raw_vault);
            
            bool found = false;
            for (const auto& e : entries) {
                if (e.url == target) {
                    clipboard_set(e.password);
                    std::cout << "🦔 password for '" << target << "' copied to clipboard!\n";
                    
                    clipboard_clear_delayed(20);
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                std::cerr << "error: '" << target << "' not found in the vault.\n";
                return 1;
            }
        }
        else if (cmd == "generate") {
            std::string new_pass = generate_password(20);
            std::cout << "🦔 generated password: " << new_pass << "\n";
            std::cout << "(warning: copy it, it's not saved in the vault yet!)\n";
        }
        else {
            print_usage();
            return 1;
        }
    } 
    catch (const std::exception& e) {
        std::cerr << "fatal error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
