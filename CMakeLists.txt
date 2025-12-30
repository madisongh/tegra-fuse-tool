cmake_minimum_required(VERSION 3.17)
project(tegra-fuse-tool LANGUAGES C VERSION 2.0.0)

set(CMAKE_C_STANDARD 11)
include(GNUInstallDirs)



add_library(tegra-fuse STATIC tegra-fuse.c tegra-fuse.h)
add_executable(tegra-fuse-tool tegra-fuse-tool.c)
target_compile_definitions(tegra-fuse-tool PRIVATE _GNU_SOURCE)
target_link_libraries(tegra-fuse-tool tegra-fuse)

install(TARGETS tegra-fuse-tool RUNTIME)
