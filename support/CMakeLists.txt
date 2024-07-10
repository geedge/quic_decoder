# CMakeFiles for 3rd vendor library

include(ExternalProject)

### OpenSSL 1.1.1
ExternalProject_Add(OpenSSL PREFIX openssl
        URL ${CMAKE_CURRENT_SOURCE_DIR}/openssl-1.1.1l.tar.gz
        URL_MD5 ac0d4387f3ba0ad741b0580dd45f6ff3
        CONFIGURE_COMMAND ./Configure  linux-x86_64 --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR>/lib/ssl enable-ec_nistp_64_gcc_128 no-shared
		BUILD_COMMAND ${MAKE_COMMAND}
		INSTALL_COMMAND make install_sw
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(OpenSSL INSTALL_DIR)
set(OPENSSL_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set(OPENSSL_LINK_DIRECTORIES ${INSTALL_DIR}/lib)
set(OPENSSL_PKGCONFIG_PATH ${INSTALL_DIR}/lib/pkgconfig/)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(openssl-crypto-static STATIC IMPORTED GLOBAL)
add_dependencies(openssl-crypto-static OpenSSL)
set_property(TARGET openssl-crypto-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libcrypto.a)
set_property(TARGET openssl-crypto-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

add_library(openssl-ssl-static STATIC IMPORTED GLOBAL)
add_dependencies(openssl-ssl-static OpenSSL)
set_property(TARGET openssl-ssl-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libssl.a)
set_property(TARGET openssl-ssl-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)