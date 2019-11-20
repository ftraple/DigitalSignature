cmake_minimum_required(VERSION 3.15)

project(DigitalSignature VERSION 1.0.0)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#-----> Enable google test

enable_testing()
add_subdirectory(googletest)
add_subdirectory(Test)
include(CTest) 

#-----> Set openssl usage

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

#-----> Encode library

set(EncodeLibrayName EncodeSignature)
add_library(${EncodeLibrayName} SHARED
    Source/Base64.cpp
    Source/EncodeSignature.cpp
)
set_target_properties(${EncodeLibrayName} PROPERTIES 
    VERSION ${PROJECT_VERSION}
    PUBLIC_HEADER Include/EncodeSignature.hpp
)
target_include_directories(${EncodeLibrayName} PRIVATE Include)
target_link_libraries(${EncodeLibrayName} OpenSSL::Crypto ${CMAKE_DL_LIBS})

#-----> Decode library

set(DecodeLibrayName DecodeSignature)
add_library(${DecodeLibrayName} SHARED
Source/Base64.cpp
Source/DecodeSignature.cpp
)
set_target_properties(${DecodeLibrayName} PROPERTIES 
    VERSION ${PROJECT_VERSION}
    PUBLIC_HEADER Include/DecodeSignature.hpp
)
target_include_directories(${DecodeLibrayName} PRIVATE Include)
target_link_libraries(${EncodeLibrayName} OpenSSL::Crypto ${CMAKE_DL_LIBS})

#-----> Install configurations
install(TARGETS ${EncodeLibrayName} ${DecodeLibrayName}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
