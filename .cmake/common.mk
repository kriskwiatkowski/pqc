# Common function for defining algorithm component
function(define_crypto_alg name namespace src inc test_src)
  add_library(
    pqclean_${name}
    OBJECT
    ${src}
  )

  target_include_directories(
    pqclean_${name} PRIVATE
    src/common
    ${inc}
  )

  target_compile_definitions(
    pqclean_${name} PRIVATE
    -DPQCLEAN_NAMESPACE=${namespace}
  )

  add_library(
    pqclean_test_${name}
    OBJECT
    ${test_src}
  )

  target_compile_definitions(
    pqclean_test_${name} PRIVATE
    -DPQCLEAN_NAMESPACE=${namespace}
  )

  target_include_directories(
    pqclean_test_${name} PRIVATE
    src/common
    ${inc}
  )

  add_executable(
    test_runner_${name}
  )
  target_link_libraries(
    test_runner_${name}

    common
    pqclean_${name}
    pqclean_test_${name}
  )
endfunction()

function(define_kem_alg name namespace src inc)
  define_crypto_alg(${name} ${namespace} "${src}" "${inc}" ${PROJECT_SOURCE_DIR}/test/kem/testvectors.c)
endfunction()
function(define_sig_alg name namespace src inc)
  define_crypto_alg(${name} ${namespace} "${src}" "${inc}" ${PROJECT_SOURCE_DIR}/test/sign/testvectors.c)
endfunction()
