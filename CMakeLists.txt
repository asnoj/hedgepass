cmake_minimum_required(VERSION 3.16)
project(hedgepass CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# Main CLI executable
add_executable(hedgepass 
    src/main.cpp
    src/secure_buffer.cpp
    src/crypto.cpp
    src/secure_input.cpp
    src/database.cpp
    src/generator.cpp
    src/clipboard.cpp
    src/file_io.cpp
)
target_link_libraries(hedgepass PRIVATE PkgConfig::SODIUM)

target_compile_options(hedgepass PRIVATE
    -Wall -Wextra -Wpedantic -Werror
    -fstack-protector-strong)

option(SANITIZE "ASan + UBSan" OFF)
if(SANITIZE)
    target_compile_options(hedgepass PRIVATE
        -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
    target_link_options(hedgepass PRIVATE -fsanitize=address,undefined)
else()
    target_compile_options(hedgepass PRIVATE
        -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
endif()

# Unit Tests target
add_executable(hedgepass_test 
    src/tests.cpp
    src/secure_buffer.cpp
    src/crypto.cpp
    src/database.cpp
)
target_link_libraries(hedgepass_test PRIVATE PkgConfig::SODIUM)
target_compile_options(hedgepass_test PRIVATE
    -Wall -Wextra -Wpedantic -Werror
    -fstack-protector-strong)
if(SANITIZE)
    target_compile_options(hedgepass_test PRIVATE
        -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
    target_link_options(hedgepass_test PRIVATE -fsanitize=address,undefined)
else()
    target_compile_options(hedgepass_test PRIVATE
        -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
endif()

# Fuzzing target: cmake -DFUZZ=ON ..
option(FUZZ "Build libFuzzer target" OFF)
if(FUZZ)
    add_executable(hedgepass_fuzz 
        src/fuzz_target.cpp
        src/secure_buffer.cpp
        src/crypto.cpp
        src/database.cpp
    )
    target_link_libraries(hedgepass_fuzz PRIVATE PkgConfig::SODIUM)
    target_compile_options(hedgepass_fuzz PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -g -fsanitize=fuzzer,address,undefined)
    target_link_options(hedgepass_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
endif()