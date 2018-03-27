cmake_minimum_required(VERSION 3.8)
project(glyph)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 99)

include_directories(/usr/local/opt/openssl/include)
link_directories(/usr/local/opt/openssl/lib)

add_definitions(-DGLP_N=1024)
add_executable(glyph
        FFT/FFT_1024_59393.c
        FFT/FFT_1024_59393.h
        FFT/FFT_includes.h
        aes/aes_ctr.c
        glp.c
        glp.h
        sha256.c
        sha256.h
        glp_consts.h
        glp_consts_1024.h
        glp_rand.c
        glp_rand.h
        glp_rand_openssl_aes.c
        glp_rand_openssl_aes.h
        glp_utils.c
        glp_utils.h
        test.c
        test_vectors.c
        test_vectors.h
        test_vectors_1024.h aes/aes_locl.h)

target_link_libraries(glyph crypto)