cmake_minimum_required (VERSION 2.8...3.10)

file(GLOB SRC "*.cpp")
set(DEPEND_DYN_LIB MESA_handle_logger)

include_directories(/opt/tsg/framework/include/)

# Shared Library Output
add_library(${lib_name} SHARED ${SRC})
set_target_properties(${lib_name} PROPERTIES LINK_FLAGS "-Wl,--version-script=${PROJECT_SOURCE_DIR}/src/version.map")
set_target_properties(${lib_name}  PROPERTIES PREFIX "")
target_link_libraries(${lib_name} ${DNS_DEPEND_DYN_LIB} pthread -Wl,--no-whole-archive  openssl-crypto-static -Wl,--no-whole-archive  openssl-ssl-static)
set_target_properties(${lib_name} PROPERTIES OUTPUT_NAME ${lib_name})

install(TARGETS ${lib_name} LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/sapp/stellar_plugin/quic_decoder COMPONENT LIBRARIES)
