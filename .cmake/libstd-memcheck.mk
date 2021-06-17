include(ExternalProject)
string (REPLACE " " "$<SEMICOLON>" LLVM_PROJECT_TARGETS "libcxx libcxxabi")
set(PREFIX ${CMAKE_CURRENT_BINARY_DIR}/3rd/llvm-project)
ExternalProject_Add(
  llvm-project
  GIT_REPOSITORY    https://github.com/llvm/llvm-project.git
  GIT_TAG           llvmorg-12.0.0
  GIT_SHALLOW       TRUE
  CMAKE_ARGS        -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS=${LLVM_PROJECT_TARGETS} -DLLVM_USE_SANITIZER=MemoryWithOrigins -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ../llvm-project/llvm
  BUILD_COMMAND     make cxx cxxabi
  INSTALL_COMMAND   DESTDIR=${PREFIX} make install-cxx-headers install-cxx install-cxxabi
  COMMENT           "Building memcheck instrumented libc++ and libc++abi"
  PREFIX            ${PREFIX}
)
