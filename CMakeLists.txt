cmake_minimum_required (VERSION 2.8...3.10)

set(lib_name quic_decoder)

project (${lib_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -Wall)

#for ASAN
set(ASAN_OPTION "OFF" CACHE STRING " set asan type chosen by the user, using OFF as default")
set_property(CACHE ASAN_OPTION  PROPERTY STRINGS OFF ADDRESS THREAD)
message(STATUS "ASAN_OPTION='${ASAN_OPTION}'")

if(ASAN_OPTION MATCHES "ADDRESS")
    set(CMAKE_C_FLAGS "${CMAKADDRESS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ASAN_OPTION MATCHES "THREAD")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()
# end of for ASAN

set(CMAKE_INSTALL_PREFIX /opt/tsg)

include_directories(include)
include_directories(/opt/MESA/include/MESA/)

add_subdirectory(support)
add_subdirectory(src)

enable_testing()
add_subdirectory(test)

set(CPACK_RPM_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/sapp/conf/quic_decoder/quic.conf"
							"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/sapp/conf/quic_decoder/main.conf")

install(FILES bin/quic.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/sapp/conf/quic_decoder COMPONENT PROFILE)
install(FILES bin/main.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/sapp/conf/quic_decoder COMPONENT PROFILE)
install(FILES include/quic_decoder.h DESTINATION ${CMAKE_INSTALL_PREFIX}/framework/include/quic_decoder COMPONENT HEADER)

include(Package)
