# PQ Crypto Catalog

This is a repository of post-quantum schemes copied from either the submission to the NIST Post-Quantum Standardization or [PQClean](https://github.com/PQClean/PQClean) project. The goal of the library is to provide easy to use API which enables quick experimentation with some post-quantum cryptographic schemes.

Users shouldn't expect any level of security provided by this code. The library is not meant to be used on live production systems.

## Schemes support

| Name                     | NIST Round | x86 optimized |
|--------------------------|------------|---------------|
| Kyber                    | 3          |  x |
| NTRU                     | 3          |  x |
| SABER                    | 3          |  x |
| FrodoKEM                 | 3          |    |
| NTRU Prime               | 3          |  x |
| HQC-RMRS                 | 3          |  x |
| Dilithium                | 3          |  x |
| Falcon                   | 2          |    |
| Rainbow                  | 3          |    |
| SPHINCS+ SHA256/SHAKE256 | 3          |  x |
| SIKE/p434                | 3          |  x |

## Building

CMake is used to build the library:

```bash
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

    p = pqc_sig_alg_by_id(DILITHIUM2);
    size_t sigsz = sig.capacity();
    pqc_keygen(p, pk.data(), sk.data());
    pqc_sig_create(p, sig.data(), &sigsz, msg.data(), msg.size(), sk.data());
    pqc_sig_verify(p, sig.data(), sig.size(), msg.data(), msg.size(), pk.data());
```

See test implemetnation in ``test/ut.cpp`` for more details.

## Rust binding

Rust bindgings are provided in the ``src/rustapi/pqc-sys`` and can be regenerated automatically by running ``cargo build`` in that directory.

## Testing against Known Answer Tests

Algorithms are tested against KATs, by the Rust-based runner implemented in the ``test/katrunner`` (only verification/decpaulation). The runner uses ``katwalk`` crate for parsing NIST format. To run it:

```bash
    cd test/katrunner
    curl http://amongbytes.com/~flowher/permalinks/kat.zip --output kat.zip
    unzip kat.zip
    cargo run -- --katdir KAT

```
