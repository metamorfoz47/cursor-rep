cmake_minimum_required(VERSION 3.15)
project(astra_proxy C)

add_library(astra SHARED proxy.c)
# Use module definition file for exports/forwarders
set_target_properties(astra PROPERTIES LINK_FLAGS "/DEF:proxy.def")

if(MINGW)
  # With MinGW, also pass the def file to the linker explicitly
  target_link_options(astra PRIVATE "-Wl,proxy.def")
endif()
