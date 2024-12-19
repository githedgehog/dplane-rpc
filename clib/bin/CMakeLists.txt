SET(CMAKE_C_FLAGS -fPIC)
set(BUILD_LIB_DEPS dplane-rpc)
add_executable(cpmock cpmock.c ../test/object_builders.c)
target_link_libraries(cpmock ${BUILD_LIB_DEPS})
