# library sources
set(LIB_SRC
    common.c
    buffer.c
    wire.c
	dp_objects.c
	dp_msg.c
	vec.c
)
set(VERBOSE false)
set(CMAKE_VERBOSE_MAKEFILE false)

message(STATUS "Compile opts ${COMPILE_OPTIONS}")

add_library(dplane-rpc SHARED ${LIB_SRC})
target_compile_options(dplane-rpc PRIVATE ${BUILD_OPTS})
target_include_directories(dplane-rpc PRIVATE "${PROJECT_BINARY_DIR}")
install(TARGETS dplane-rpc DESTINATION /usr/local/lib/frr/modules)
