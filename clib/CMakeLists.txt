cmake_minimum_required(VERSION 3.24)
project(DPLANE-RPC
    VERSION 0.0.1
    DESCRIPTION "Wire format for HH GW DP-CP communications"
    LANGUAGES C)

if (NOT DEFINED MAX_ECMP)
    message(STATUS "MAX_ECMP is not set. Defaulting it ..")
    set(MAX_ECMP 32)
endif ()

message(STATUS "MAX_ECMP is ${MAX_ECMP}")
add_definitions(-DMAX_ECMP=${MAX_ECMP} -Wall -Werror)


include(CTest)
add_subdirectory(src)
add_subdirectory(test)
