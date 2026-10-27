cmake_minimum_required(VERSION 3.20)
project(nockx-base)

set(OPENSSL_USE_STATIC_LIBS OFF)
find_package(OpenSSL 3.5 REQUIRED)

add_library(nockx-base SHARED library.cpp
        aes_crypto.cpp
        secure_key.h
        rsa_crypto.cpp
        kem_crypto.cpp
        dsa_crypto.cpp
        asymmetric_key.h)

target_link_libraries(nockx-base PRIVATE OpenSSL::SSL OpenSSL::Crypto)
set_property(TARGET nockx-base PROPERTY CXX_STANDARD 20)

set_target_properties(nockx-base PROPERTIES PREFIX "lib")

if(APPLE)
    set_target_properties(nockx-base PROPERTIES
            BUILD_WITH_INSTALL_RPATH ON INSTALL_RPATH "@loader_path")
elseif(UNIX)
    set_target_properties(nockx-base PROPERTIES
            BUILD_WITH_INSTALL_RPATH ON INSTALL_RPATH "$ORIGIN")
endif()

if(WIN32)
    set_property(TARGET nockx-base PROPERTY WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

install(TARGETS nockx-base RUNTIME DESTINATION . LIBRARY DESTINATION .)