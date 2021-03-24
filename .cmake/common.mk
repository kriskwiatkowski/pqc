# Common function for defining algorithm component
function(define_crypto_alg name namespace src inc)
  get_property(OBJ_LIBS GLOBAL PROPERTY obj_libs)
  set_property(GLOBAL PROPERTY obj_libs ${OBJ_LIBS} pqclean_${name})

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

endfunction()

function(define_kem_alg name namespace src inc)
  define_crypto_alg(${name} ${namespace} "${src}" "${inc}")
endfunction()
function(define_sig_alg name namespace src inc)
  define_crypto_alg(${name} ${namespace} "${src}" "${inc}")
endfunction()
