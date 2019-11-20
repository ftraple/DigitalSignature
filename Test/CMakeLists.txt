cmake_minimum_required(VERSION 3.15)

set(This MyTest)

set(Source
    Test.cpp
)

add_executable(${This} ${Source})
target_link_libraries(${This}
    gtest_main
    EncodeSignature
    DecodeSignature
)

add_test(
    NAME ${This}
    COMMAND ${This}
)

