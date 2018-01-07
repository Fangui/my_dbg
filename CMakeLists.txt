cmake_minimum_required(VERSION 2.8)

project(my_dbg C)
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_C_FLAGS "-Wall -Wextra -std=c99 -pedantic -g -D_XOPEN_SOURCE -D_DEFAULT_SOURCE -D_GNU_SOURCE")
include_directories("src")

set(SRC
    src/breakpoint.c
    src/cmd_breakpoint.c
    src/commands.c
    src/commands_utils.c
    src/disassemble.c
    src/info_commands.c
    src/main.c
    src/interactive.c
    src/parser.c
   )

add_custom_target(check
WORKING_DIRECTORY ../tests
COMMAND ./test.py)
add_executable(my_dbg ${SRC})
target_link_libraries(my_dbg readline unwind unwind-x86_64 unwind-ptrace wayland-client capstone)
