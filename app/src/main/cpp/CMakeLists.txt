cmake_minimum_required(VERSION 3.22.1)
project(tlswatchdog C)

add_library(tlswatchdog SHARED
        native_bridge.c
        zdtun/zdtun.c
        zdtun/utils.c)

target_include_directories(tlswatchdog PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/zdtun)

# ANDROID -> zdtun logs via android/log.h. Keep logging on for Phase 0 bring-up.
target_compile_definitions(tlswatchdog PRIVATE ANDROID)
target_compile_options(tlswatchdog PRIVATE -Wall -Wno-unused-function -O2)

find_library(log-lib log)
target_link_libraries(tlswatchdog ${log-lib})
