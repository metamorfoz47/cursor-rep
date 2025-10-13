cmake_minimum_required(VERSION 3.15)
project(astra_proxy C)

# Add proxy sources and def file
add_library(astra SHARED proxy.c proxy.def)
set_target_properties(astra PROPERTIES OUTPUT_NAME "astra" PREFIX "")

# Link against Winsock for send/recv/connect, WSAGetLastError, etc.
if(MSVC)
  target_link_libraries(astra PRIVATE ws2_32 user32)
  # Use module definition file for exports/forwarders
  target_link_options(astra PRIVATE "/DEF:proxy.def")
else()
  target_link_libraries(astra PRIVATE ws2_32 user32)
  # For MinGW toolchains, adding the .def file as a source is sufficient
endif()
