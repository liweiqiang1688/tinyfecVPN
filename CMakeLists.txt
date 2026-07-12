#note: experimental
#      currently only used for generating `compile_commands.json` for clangd
#      to build this project, it's suggested to use `makefile` instead

cmake_minimum_required(VERSION 3.7)
project(tinyvpn)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        UDPspeeder/log.cpp
        UDPspeeder/common.cpp
        UDPspeeder/lib/fec.cpp
        UDPspeeder/lib/rs.cpp
        UDPspeeder/packet.cpp
        UDPspeeder/delay_manager.cpp
        UDPspeeder/fd_manager.cpp
        UDPspeeder/connection.cpp
        UDPspeeder/fec_manager.cpp
        UDPspeeder/misc.cpp
        UDPspeeder/my_ev.cpp
        main.cpp
        tun_dev_client.cpp
        tun_dev_server.cpp
        tun_dev.cpp
        tun_dev_raw_client.cpp
        tun_dev_raw_server.cpp
)

# tun_dev_raw.cpp is compiled separately with udp2raw headers
# to avoid symbol conflicts with UDPspeeder
add_library(tun_dev_raw_obj OBJECT tun_dev_raw.cpp)
target_include_directories(tun_dev_raw_obj PRIVATE "udp2raw")
target_include_directories(tun_dev_raw_obj SYSTEM PRIVATE "udp2raw/libev")

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers -O2 -g -fsanitize=address,undefined")

add_executable(tinyvpn ${SOURCE_FILES} $<TARGET_OBJECTS:tun_dev_raw_obj>)
target_link_libraries(tinyvpn rt)
target_link_libraries(tinyvpn pthread)
include_directories(SYSTEM "UDPspeeder/libev")
include_directories("UDPspeeder")
include_directories(".")
