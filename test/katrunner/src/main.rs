use katwalk::reader::{Kat, AlgType, TestVector, KatReader};
use std::{fs::File, io::BufReader};
use pqc_sys::*;
use std::env;
use std::path::Path;
use threadpool::ThreadPool;

// Used for signature algorithm registration
macro_rules! REG_SIGN {
    ($ID:expr,$F:expr) => {
        Register{
            kat:Kat{
                scheme_type: AlgType::AlgSignature,
                scheme_id: $ID,
                kat_file: $F},
                execfn: test_sign_vector}
    }
}

macro_rules! REG_KEM {
    ($ID:expr,$F:expr) => {
        Register{
            kat:Kat{
                scheme_type: AlgType::AlgKem,
                scheme_id: $ID,
                kat_file: $F},
                execfn: test_kem_vector}
    }
}

const KAT_DIR : &'static str= ".";
type ExecFn = fn(&TestVector);
struct Register {
    kat: katwalk::reader::Kat,
    execfn: ExecFn,
}

fn test_sign_vector(el: &TestVector) {
    unsafe {
        let p = pqc_sig_alg_by_id(el.scheme_id as u8);
        assert_ne!(p.is_null(), true);
        // pqc doesn't use "envelope" API. From the other
        // hand in KATs for signature scheme, the signature
        // is concatenaed with a message. Use only part with
        // the signature.
        let sm_len = el.sig.sm.len() - el.sig.msg.len();
        assert_eq!(
            pqc_sig_verify(p,
                el.sig.sm.as_ptr(), sm_len as u64,
                el.sig.msg.as_ptr(), el.sig.msg.len() as u64,
                el.sig.pk.as_ptr()),
            true);
    }
}

fn test_kem_vector(el: &TestVector) {
    let mut ss = Vec::new();

    ss.resize(el.kem.ss.len(), 0);
    unsafe {
        let p = pqc_kem_alg_by_id(el.scheme_id as u8);
        assert_ne!(p.is_null(), true);
        assert_eq!(
            pqc_kem_decapsulate(p, ss.as_mut_ptr(), el.kem.ct.as_ptr(), el.kem.sk.as_ptr()),
            true);
    }
}

// KAT test register
const KATS: &'static[Register] = &[
    REG_SIGN!(DILITHIUM2, "round3/dilithium/dilithium2/PQCsignKAT_2544.rsp"),
    REG_SIGN!(DILITHIUM3, "round3/dilithium/dilithium3/PQCsignKAT_4016.rsp"),
    REG_SIGN!(DILITHIUM5, "round3/dilithium/dilithium5/PQCsignKAT_4880.rsp"),
    //REG_SIGN!(FALCON512,  "round3/falcon/falcon512-KAT.rsp"),
    //REG_SIGN!(FALCON1024, "round3/falcon/falcon1024-KAT.rsp"),

    // Some implementations of sphincs are for round3
    REG_SIGN!(SPHINCSSHA256128SSIMPLE,"round3/sphincs/sphincs-sha256-128s-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHA256128SROBUST,"round3/sphincs/sphincs-sha256-128s-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHA256128FSIMPLE,"round3/sphincs/sphincs-sha256-128f-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHA256128FROBUST,"round3/sphincs/sphincs-sha256-128f-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHA256192SSIMPLE,"round3/sphincs/sphincs-sha256-192s-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHA256192SROBUST,"round3/sphincs/sphincs-sha256-192s-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHA256192FSIMPLE,"round3/sphincs/sphincs-sha256-192f-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHA256192FROBUST,"round3/sphincs/sphincs-sha256-192f-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHA256256SSIMPLE,"round3/sphincs/sphincs-sha256-256s-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHA256256SROBUST,"round3/sphincs/sphincs-sha256-256s-robust/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHA256256FROBUST,"round3/sphincs/sphincs-sha256-256f-robust/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHA256256FSIMPLE,"round3/sphincs/sphincs-sha256-256f-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHAKE256128FSIMPLE,"round3/sphincs/sphincs-shake256-128f-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHAKE256128SSIMPLE,"round3/sphincs/sphincs-shake256-128s-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHAKE256128FROBUST,"round3/sphincs/sphincs-shake256-128f-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHAKE256128SROBUST,"round3/sphincs/sphincs-shake256-128s-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHAKE256192FROBUST,"round3/sphincs/sphincs-shake256-192f-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHAKE256192FSIMPLE,"round3/sphincs/sphincs-shake256-192f-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHAKE256192SSIMPLE,"round3/sphincs/sphincs-shake256-192s-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHAKE256192SROBUST,"round3/sphincs/sphincs-shake256-192s-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHAKE256256FROBUST,"round3/sphincs/sphincs-shake256-256f-robust/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHAKE256256FSIMPLE,"round3/sphincs/sphincs-shake256-256f-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHAKE256256SSIMPLE,"round3/sphincs/sphincs-shake256-256s-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHAKE256256SROBUST,"round3/sphincs/sphincs-shake256-256s-robust/PQCsignKAT_128.rsp"),

    // KEM Schemes
    REG_KEM!(FRODOKEM640SHAKE, "round3/frodokem/PQCkemKAT_19888_shake.rsp"),
    REG_KEM!(FRODOKEM976SHAKE, "round3/frodokem/PQCkemKAT_31296_shake.rsp"),
    REG_KEM!(FRODOKEM1344SHAKE, "round3/frodokem/PQCkemKAT_43088_shake.rsp"),
    REG_KEM!(KYBER768, "round3/kyber/kyber768/PQCkemKAT_2400.rsp"),
    REG_KEM!(KYBER1024, "round3/kyber/kyber1024/PQCkemKAT_3168.rsp"),
    REG_KEM!(KYBER512, "round3/kyber/kyber512/PQCkemKAT_1632.rsp"),
    REG_KEM!(NTRUHPS4096821, "round3/ntru/ntruhps4096821/PQCkemKAT_1590.rsp"),
    REG_KEM!(NTRUHPS2048509, "round3/ntru/ntruhps2048509/PQCkemKAT_935.rsp"),
    REG_KEM!(NTRUHRSS701, "round3/ntru/ntruhrss701/PQCkemKAT_1450.rsp"),
    REG_KEM!(NTRUHPS2048677, "round3/ntru/ntruhps2048677/PQCkemKAT_1234.rsp"),
    REG_KEM!(NTRULPR761, "round3/ntrup/ntrulpr761/kat_kem.rsp"),
    REG_KEM!(NTRULPR653, "round3/ntrup/ntrulpr653/kat_kem.rsp"),
    REG_KEM!(NTRULPR857, "round3/ntrup/ntrulpr857/kat_kem.rsp"),
    REG_KEM!(LIGHTSABER, "round3/saber/LightSaber/PQCkemKAT_1568.rsp"),
    REG_KEM!(FIRESABER, "round3/saber/FireSaber/PQCkemKAT_3040.rsp"),
    REG_KEM!(SABER, "round3/saber/Saber/PQCkemKAT_2304.rsp"),
    REG_KEM!(HQCRMRS128, "round3/hqc/hqc-128/hqc-128_kat.rsp"),
    REG_KEM!(HQCRMRS192, "round3/hqc/hqc-192/hqc-192_kat.rsp"),
    REG_KEM!(HQCRMRS256, "round3/hqc/hqc-256/hqc-256_kat.rsp"),

    // Those are Round2. KATs are very big, so skip testing until it makes sense to do so.
    //REG_SIGN!(RAINBOWVCLASSIC),
    //REG_SIGN!(RAINBOWICLASSIC),
    //REG_SIGN!(RAINBOWIIICLASSIC),
];

fn execute(kat_dir: String) {
    // Can't do multi-threads as DRBG context is global
    let pool = ThreadPool::new(1);
    for k in KATS.iter() {
        let tmp = kat_dir.clone();
        pool.execute(move || {
            let f = Path::new(&tmp.to_string()).join(k.kat.kat_file);
            let file = File::open(format!("{}", f.to_str().unwrap()));
            println!("Processing file: {}", Path::new(k.kat.kat_file).to_str().unwrap());
            let b = BufReader::new(file.unwrap());

            for el in KatReader::new(b, k.kat.scheme_type, k.kat.scheme_id) {
                (k.execfn)(&el);
            }
        });
    }
    pool.join();
}

fn main() {
    let kat_dir: String;
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        if args[1] == "--katdir" && args.len() == 3 {
            kat_dir = args[2].to_string();
        } else {
            panic!("Unrecognized argument");
        }
    } else {
        kat_dir = String::from(KAT_DIR);
    }
    execute(kat_dir);
}
