cmake_minimum_required (VERSION 3.8)

project("lib_test")

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

add_definitions(-DUNICODE -D_UNICODE)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj /permissive -D_YOU_WANT ")

message("CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
if (CMAKE_BUILD_TYPE MATCHES "Rel")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_IM_RELEASE")
endif()
message("CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS}")

include_directories(
	"../include/"
)

link_directories(
	"../libs/win/"
)

add_executable (test_http
	"http.cpp"
)

target_link_libraries (test_http PRIVATE
	"libcrypto.lib"
	"libssl.lib"
	"crypt32.lib"
)