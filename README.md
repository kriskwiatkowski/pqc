# PQ Crypto Catalog

This is a repository of post-quantum schemes copied from the submission to the NIST Post-Quantum Standardization. The sources were initially based on the PQClean project to form a new library. The goal of the library is to be used mainly for experimentation or implementation of various PoC related to migration to post-quantum cryptography.

Users shouldn't expect any level of security provided by this code. The library is not meant to be used on live production systems.

## Schemes

### Key Encapsulation Mechanisms

**Finalists:**
* Kyber
* NTRU
* SABER

**Alternate candidates:**
* FrodoKEM

### Signature schemes

**Finalists:**
* Dilithium
* Falcon
* Rainbow

**Alternate candidates:**
* SPHINCS+

## Building

CMake is used to build the library:

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

Build outputs two libraries, a static ``libpqc_s.a`` and dynamic ``libpqc.so``, which can be linked with a project.

## API

Library provides simple API, wrapping PQClean. For example to use KEM, one should call the library in following way:
```c
    #include <pqc/pqc.h>

    std::vector<uint8_t> ct(ciphertext_bsz(p));
    std::vector<uint8_t> ss1(shared_secret_bsz(p));
    std::vector<uint8_t> ss2(shared_secret_bsz(p));
    std::vector<uint8_t> sk(private_key_bsz(p));
    std::vector<uint8_t> pk(public_key_bsz(p));

    const params_t *p = pqc_kem_alg_by_id(KYBER512);
    pqc_keygen(p, pk.data(), sk.data());
    pqc_kem_encapsulate(p, ct.data(), ss1.data(), pk.data());
    pqc_kem_decapsulate(p, ss2.data(), ct.data(), sk.data());
    
    const params_t *p = pqc_sig_alg_by_id(DILITHIUM2);
    size_t sigsz = sig.capacity();
    pqc_keygen(p, pk.data(), sk.data());
    pqc_sig_create(p, sig.data(), &sigsz, msg.data(), msg.size(), sk.data());
    pqc_sig_verify(p, sig.data(), sig.size(), msg.data(), msg.size(), pk.data());
```

See test implemetnation in ``test/ut.cpp`` for more details.

## Rust binding

Rust bindgings are provided in the ``src/rustapi/pqc-sys`` and can be regenerated automatically by running ``cargo build`` in this directory.

## Testing

Algorithms are tested against KATs, by the runner implemented in the ``teste/katrunner`` (wip). The runner uses ``katwalk`` crate.
