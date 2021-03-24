# PQ Crypto Catalog

This is a repository of post-quantum schemes coppied from the submission to the NIST Post-Quantum Standarization. The sources were cloned from the PQClean project to form new library. The goal of the library is mainly experimentation.

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

