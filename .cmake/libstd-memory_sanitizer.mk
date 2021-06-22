include(ExternalProject)
find_program(MAKE_PROGRAM make)

string (REPLACE " " "$<SEMICOLON>" LLVM_PROJECT_TARGETS "libcxx libcxxabi")
set(PREFIX ${CMAKE_CURRENT_BINARY_DIR}/3rd/llvm-project)
set(LLVM_LIB_CXX
    ${PREFIX}/usr/local/lib/libc++${CMAKE_STATIC_LIBRARY_SUFFIX})
set(LLVM_LIB_CXXABI
    ${PREFIX}/usr/local/lib/libc++abi${CMAKE_STATIC_LIBRARY_SUFFIX})

ExternalProject_Add(
  llvm-project
  GIT_REPOSITORY    https://github.com/llvm/llvm-project.git
  GIT_TAG           llvmorg-12.0.0
  GIT_SHALLOW       TRUE
  CMAKE_ARGS        -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS=${LLVM_PROJECT_TARGETS} -DLLVM_USE_SANITIZER=MemoryWithOrigins -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ../llvm-project/llvm -DLLVM_INCLUDE_BENCHMARKS=OFF
  BUILD_COMMAND     ${MAKE_PROGRAM} cxx cxxabi
  INSTALL_COMMAND   DESTDIR=${PREFIX} make install-cxx-headers install-cxx install-cxxabi
  COMMENT           "Building memcheck instrumented libc++ and libc++abi"
  PREFIX            ${PREFIX}
)

add_library(
    cxx SHARED IMPORTED GLOBAL)
add_library(
    cxxabi SHARED IMPORTED GLOBAL)

add_dependencies(
    cxx
    llvm-project)
add_dependencies(
    cxxabi
    llvm-project)

set_target_properties(
    cxx PROPERTIES IMPORTED_LOCATION ${LLVM_LIB_CXX})
set_target_properties(
    cxxabi PROPERTIES IMPORTED_LOCATION ${LLVM_LIB_CXXABI})

set_property(
  GLOBAL PROPERTY llvmproject_build_install_dir_property
  ${PREFIX}/usr/local)
