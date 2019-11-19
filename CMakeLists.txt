cmake_minimum_required(VERSION 3.15)

project(DigitalSignature VERSION 1.0.0)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(EncodeLibrayName EncodeSignature)

set(Source
    Source/EncodeSignature.cpp
)

#Generate the shared library from the sources
add_library(${EncodeLibrayName} SHARED ${Source})

set_target_properties(${EncodeLibrayName} PROPERTIES 
    VERSION ${PROJECT_VERSION}
    PUBLIC_HEADER Include/EncodeSignature.hpp
)
target_include_directories(${EncodeLibrayName} PRIVATE Include)

# Install configurations
install(TARGETS ${EncodeLibrayName}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
