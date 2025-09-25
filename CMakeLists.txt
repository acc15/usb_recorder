cmake_minimum_required(VERSION 3.10.0)
project(usb_recorder VERSION 0.1.0 LANGUAGES C)

add_executable(usb_recorder src/main.c)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libserialport REQUIRED libserialport)
target_include_directories(usb_recorder PRIVATE ${libserialport_INCLUDE_DIRS})
target_link_libraries(usb_recorder PRIVATE ${libserialport_LIBRARIES})


