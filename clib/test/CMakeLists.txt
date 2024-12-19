
set(BUILD_LIB_DEPS dplane-rpc)

add_executable(test_buffer test_buffer.c)
target_link_libraries(test_buffer ${BUILD_LIB_DEPS})
add_test(NAME test_buffer COMMAND test_buffer)

add_executable(test_vec test_vec.c)
target_link_libraries(test_vec ${BUILD_LIB_DEPS})
add_test(NAME test_vec COMMAND test_vec)

add_executable(test_wire test_wire.c object_builders.c)
target_link_libraries(test_wire ${BUILD_LIB_DEPS})
add_test(NAME test_wire COMMAND test_wire)

