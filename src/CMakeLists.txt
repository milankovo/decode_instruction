cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

project(decode_instruction)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-Wnullability-completeness"
                        COMPILER_HAS_W_NULLABILITY_COMPLETENESS)
if(COMPILER_HAS_W_NULLABILITY_COMPLETENESS)
  string(APPEND CMAKE_CXX_FLAGS " -Wno-nullability-completeness")
endif()

check_cxx_compiler_flag("-Wno-varargs" COMPILER_HAS_W_NO_VARARGS)
if(COMPILER_HAS_W_NO_VARARGS)
    string(APPEND CMAKE_CXX_FLAGS " -Wno-varargs")
endif()

if (MSVC)
  string(APPEND CMAKE_CXX_FLAGS " /O2")
  add_compile_definitions(_HAS_CXX23=1)
  add_compile_options(/Zc:__cplusplus)
endif (MSVC)

CHECK_CXX_COMPILER_FLAG("-O3" COMPILER_SUPPORTS_MARCH_NATIVE)
if(COMPILER_SUPPORTS_MARCH_NATIVE)
    string(APPEND CMAKE_CXX_FLAGS " -O3")
endif()


include($ENV{IDASDK}/ida-cmake/common.cmake)

set(PLUGIN_NAME              decode_instruction)
set(PLUGIN_SOURCES           decode_instruction.cpp)
set(PLUGIN_RUN_ARGS          "-t -z10000") # Debug messages for the debugger
generate()

disable_ida_warnings(decode_instruction)