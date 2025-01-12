# library sources
set(LIB_SRC
    common.c
    buffer.c
    wire.c
	dp_objects.c
	dp_msg.c
	vec.c
	display.c
	fmt_buff.c
)
set(VERBOSE false)
set(CMAKE_VERBOSE_MAKEFILE false)

message(STATUS "Compile opts ${COMPILE_OPTIONS}")

add_library(dplane-rpc SHARED ${LIB_SRC})
set_property(TARGET dplane-rpc PROPERTY POSITION_INDEPENDENT_CODE ON)
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
target_compile_options(dplane-rpc PRIVATE ${BUILD_OPTS})
target_include_directories(dplane-rpc PRIVATE "${PROJECT_BINARY_DIR}")

set_target_properties(dplane-rpc PROPERTIES PUBLIC_HEADER
 "buffer.h;errors.h;display.h;dplane-rpc.h;dp_msg.h;dp_objects.h;dp_types.h;proto.h;vec.h;fmt_buff.h;wire.h")

install(TARGETS dplane-rpc LIBRARY DESTINATION /usr/local/lib
	PUBLIC_HEADER DESTINATION /usr/include/dplane-rpc
)
