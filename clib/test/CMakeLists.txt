
set(BUILD_LIB_DEPS dplane-rpc)

add_executable(test_buffer test_buffer.c)
target_link_libraries(test_buffer ${BUILD_LIB_DEPS})
add_test(NAME test_buffer COMMAND test_buffer)

add_executable(test_wire test_wire.c object_builders.c)
target_link_libraries(test_wire ${BUILD_LIB_DEPS})
add_test(NAME test_wire COMMAND test_wire)

add_executable(test_fmt_buff test_fmt_buff.c object_builders.c)
target_link_libraries(test_fmt_buff ${BUILD_LIB_DEPS})
add_test(NAME test_fmt_buff COMMAND test_fmt_buff)
