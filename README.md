# PQ Crypto Catalog

This is a repository of post-quantum schemes coppied from the submission to the NIST Post-Quantum Standarization. The sources were cloned from the PQClean project to form new library. The goal of the library is mainly experimentation.

## Schemes

### Key Encapsulation Mechanisms

**Finalists:**
* Classic McEliece
* Kyber
* NTRU
* SABER

**Alternate candidates:**
* FrodoKEM
* HQC

### Signature schemes

**Finalists:**
* Dilithium
* Falcon
* Rainbow

**Alternate candidates:**
* SPHINCS+

Implementations previously available in PQClean and dropped in Round 3 of the NIST standardization effort are available in the [`round2` tag](https://github.com/PQClean/PQClean/releases/tag/round2).

## API used by PQClean

PQClean is essentially using the same API as required for the NIST reference implementations,
which is also used by SUPERCOP and by libpqcrypto. The only differences to that API are
the following:
* All functions are namespaced;
* All lengths are passed as type `size_t` instead of `unsigned long long`; and
* Signatures offer two additional functions that follow the "traditional" approach used
in most software stacks of computing and verifying signatures instead of producing and
recovering signed messages. Specifically, those functions have the following name and signature:

```c
int PQCLEAN_SCHEME_IMPL_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *sk);
int PQCLEAN_SCHEME_IMPL_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *pk);
```
