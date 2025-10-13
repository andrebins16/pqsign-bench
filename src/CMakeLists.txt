cmake_minimum_required(VERSION 3.16)
project(pqc_bench_full C)
set(CMAKE_C_STANDARD 11)

find_package(OpenSSL 3.0 REQUIRED)

# Core
add_library(crypto_core STATIC crypto_core.c)
target_link_libraries(crypto_core PUBLIC OpenSSL::Crypto)
target_include_directories(crypto_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# bench_worker
add_executable(bench_worker bench_worker.c)
target_link_libraries(bench_worker PRIVATE crypto_core OpenSSL::Crypto)

# bench_prep
add_executable(bench_prep bench_prep.c)
target_link_libraries(bench_prep PRIVATE crypto_core OpenSSL::Crypto)