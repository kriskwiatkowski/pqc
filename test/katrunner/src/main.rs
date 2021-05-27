use katwalk::reader::{Kat, AlgType, TestVector, KatReader};
use std::{fs::File, io::BufReader};
use pqc_sys::*;
use std::env;
use std::path::Path;
use threadpool::ThreadPool;
use std::convert::TryInto;
use aes_ctr_drbg::DrbgCtx;
use std::collections::HashMap;
use std::thread;
use std::sync::Mutex;
use lazy_static::lazy_static;

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

// Stores one DRBG context per execution thread. DRBG
// is inserted in this map, just after thread starts
// and removed after thread is finished. Operation
// is synchronized.
lazy_static! {
    static ref DRBGV: Mutex<HashMap<thread::ThreadId, DrbgCtx>> = Mutex::new(HashMap::new());
}

// We have to provide the implementation for randombytes
#[no_mangle]
unsafe extern "C" fn randombytes(
    data: *mut ::std::os::raw::c_uchar,
    len: usize
) {
    let mut slice = std::slice::from_raw_parts_mut(data, len);
    // get thread specific DRBG.
    if let Some(drbg) = DRBGV.lock().unwrap().get_mut(&thread::current().id()) {
        drbg.get_random(&mut slice);
    }

}

type ExecFn = fn(&TestVector);
struct Register {
    kat: katwalk::reader::Kat,
    execfn: ExecFn,
}

fn test_sign_vector(el: &TestVector) {
    let mut pk = Vec::new();
    let mut sk = Vec::new();
    let mut sm = Vec::new();

    if let Some(drbg) = DRBGV.lock().unwrap().get_mut(&thread::current().id()) {
        drbg.init(el.sig.seed.as_slice(), Vec::new());
    }

    unsafe {
        // Check Verification
        // pqc doesn't use "envelope" API. From the other
        // hand in KATs for signature scheme, the signature
        // is concatenaed with a message. Use only part with
        // the signature.
        let sm_len = el.sig.sm.len() - el.sig.msg.len();

        let p = pqc_sig_alg_by_id(el.scheme_id as u8);
        assert_ne!(p.is_null(), true);

        // Check keygen
        pk.resize(el.sig.pk.len(), 0);
        sk.resize(el.sig.sk.len(), 0);
        assert_eq!(
            pqc_keygen(p, pk.as_mut_ptr(), sk.as_mut_ptr()),
            true);
        assert_eq!(sk, el.sig.sk);
        assert_eq!(pk, el.sig.pk);

        // Check signing
        sm.resize(sm_len, 0);
        let mut siglen: u64 = sm_len.try_into().unwrap();
        assert_eq!(
            pqc_sig_create(p, sm.as_mut_ptr(), &mut siglen,
                el.sig.msg.as_ptr(), el.sig.msg.len().try_into().unwrap(),
                el.sig.sk.as_ptr()),
            true);
        if el.scheme_id == PQC_ALG_SIG_FALCON512 || el.scheme_id == PQC_ALG_SIG_FALCON1024 {
            // In case of falcon we encode the variable size differently
            assert_eq!(&sm[2..42], &el.sig.sm[2..42], "Signature: nonce wrong");
            assert_eq!(&sm[42..], &el.sig.sm[42+el.sig.msg.len()..], "Signature: nonce wrong");
        } else {
            assert_eq!(siglen, sm_len.try_into().unwrap());
            assert_eq!(sm, &el.sig.sm[0..sm.len()], "Signature wrong");
        }
        // Check verification
        assert_eq!(
            pqc_sig_verify(p,
                sm.as_ptr(), siglen,
                el.sig.msg.as_ptr(), el.sig.msg.len() as u64,
                el.sig.pk.as_ptr()),
            true);
    }
}

fn test_kem_vector(el: &TestVector) {
    let mut pk = Vec::new();
    let mut sk = Vec::new();
    let mut ct = Vec::new();
    let mut ss = Vec::new();

    if let Some(drbg) = DRBGV.lock().unwrap().get_mut(&thread::current().id()) {
        drbg.init(el.kem.seed.as_slice(), Vec::new());
    }

    unsafe {

        let p = pqc_kem_alg_by_id(el.scheme_id as u8);
        assert_ne!(p.is_null(), true);

        // Check keygen
        pk.resize(el.kem.pk.len(), 0);
        sk.resize(el.kem.sk.len(), 0);
        assert_eq!(
            pqc_keygen(p, pk.as_mut_ptr(), sk.as_mut_ptr()),
        true);

        assert_eq!(sk, el.kem.sk);
        assert_eq!(pk, el.kem.pk);

        // Check encapsulation
        ss.resize(el.kem.ss.len(), 0);
        ct.resize(el.kem.ct.len(), 0);
        assert_eq!(
            pqc_kem_encapsulate(p,
                ct.as_mut_ptr(), ss.as_mut_ptr(), el.kem.pk.as_ptr()),
            true);
        assert_eq!(ct, el.kem.ct);
        assert_eq!(ss, el.kem.ss);

        // Check decapsulation
        ss.clear();
        ss.resize(el.kem.ss.len(), 0);
        assert_eq!(
            pqc_kem_decapsulate(p,
                ss.as_mut_ptr(), el.kem.ct.as_ptr(), el.kem.sk.as_ptr()),
            true);
        assert_eq!(ss, el.kem.ss);
    }
}

// KAT test register
const KATS: &'static[Register] = &[
    REG_SIGN!(PQC_ALG_SIG_DILITHIUM2, "round3/dilithium/dilithium2/PQCsignKAT_2544.rsp"),
    REG_SIGN!(PQC_ALG_SIG_DILITHIUM3, "round3/dilithium/dilithium3/PQCsignKAT_4016.rsp"),
    REG_SIGN!(PQC_ALG_SIG_DILITHIUM5, "round3/dilithium/dilithium5/PQCsignKAT_4880.rsp"),
    REG_SIGN!(PQC_ALG_SIG_FALCON512,  "round3/falcon/falcon512-KAT.rsp"),
    REG_SIGN!(PQC_ALG_SIG_FALCON1024, "round3/falcon/falcon1024-KAT.rsp"),

    // Some implementations of sphincs are for round3
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256128SSIMPLE,"round3/sphincs/sphincs-sha256-128s-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256128SROBUST,"round3/sphincs/sphincs-sha256-128s-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256128FSIMPLE,"round3/sphincs/sphincs-sha256-128f-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256128FROBUST,"round3/sphincs/sphincs-sha256-128f-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256192SSIMPLE,"round3/sphincs/sphincs-sha256-192s-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256192SROBUST,"round3/sphincs/sphincs-sha256-192s-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256192FSIMPLE,"round3/sphincs/sphincs-sha256-192f-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256192FROBUST,"round3/sphincs/sphincs-sha256-192f-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256256SSIMPLE,"round3/sphincs/sphincs-sha256-256s-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256256SROBUST,"round3/sphincs/sphincs-sha256-256s-robust/PQCsignKAT_128.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256256FROBUST,"round3/sphincs/sphincs-sha256-256f-robust/PQCsignKAT_128.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHA256256FSIMPLE,"round3/sphincs/sphincs-sha256-256f-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256128FSIMPLE,"round3/sphincs/sphincs-shake256-128f-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256128SSIMPLE,"round3/sphincs/sphincs-shake256-128s-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256128FROBUST,"round3/sphincs/sphincs-shake256-128f-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256128SROBUST,"round3/sphincs/sphincs-shake256-128s-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256192FROBUST,"round3/sphincs/sphincs-shake256-192f-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256192FSIMPLE,"round3/sphincs/sphincs-shake256-192f-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256192SSIMPLE,"round3/sphincs/sphincs-shake256-192s-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256192SROBUST,"round3/sphincs/sphincs-shake256-192s-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256256FROBUST,"round3/sphincs/sphincs-shake256-256f-robust/PQCsignKAT_128.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256256FSIMPLE,"round3/sphincs/sphincs-shake256-256f-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256256SSIMPLE,"round3/sphincs/sphincs-shake256-256s-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(PQC_ALG_SIG_SPHINCSSHAKE256256SROBUST,"round3/sphincs/sphincs-shake256-256s-robust/PQCsignKAT_128.rsp"),

    // KEM Schemes
    REG_KEM!(PQC_ALG_KEM_FRODOKEM640SHAKE, "round3/frodokem/PQCkemKAT_19888_shake.rsp"),
    REG_KEM!(PQC_ALG_KEM_FRODOKEM976SHAKE, "round3/frodokem/PQCkemKAT_31296_shake.rsp"),
    REG_KEM!(PQC_ALG_KEM_FRODOKEM1344SHAKE, "round3/frodokem/PQCkemKAT_43088_shake.rsp"),
    REG_KEM!(PQC_ALG_KEM_KYBER768, "round3/kyber/kyber768/PQCkemKAT_2400.rsp"),
    REG_KEM!(PQC_ALG_KEM_KYBER1024, "round3/kyber/kyber1024/PQCkemKAT_3168.rsp"),
    REG_KEM!(PQC_ALG_KEM_KYBER512, "round3/kyber/kyber512/PQCkemKAT_1632.rsp"),
    REG_KEM!(PQC_ALG_KEM_NTRUHPS4096821, "round3/ntru/ntruhps4096821/PQCkemKAT_1590.rsp"),
    REG_KEM!(PQC_ALG_KEM_NTRUHPS2048509, "round3/ntru/ntruhps2048509/PQCkemKAT_935.rsp"),
    REG_KEM!(PQC_ALG_KEM_NTRUHRSS701, "round3/ntru/ntruhrss701/PQCkemKAT_1450.rsp"),
    REG_KEM!(PQC_ALG_KEM_NTRUHPS2048677, "round3/ntru/ntruhps2048677/PQCkemKAT_1234.rsp"),
    // For some reason NTRUL doesn't pass the tests (keygeneration)
    //REG_KEM!(PQC_ALG_KEM_NTRULPR761, "round3/ntrup/ntrulpr761/kat_kem.rsp"),
    //REG_KEM!(PQC_ALG_KEM_NTRULPR653, "round3/ntrup/ntrulpr653/kat_kem.rsp"),
    //REG_KEM!(PQC_ALG_KEM_NTRULPR857, "round3/ntrup/ntrulpr857/kat_kem.rsp"),
    REG_KEM!(PQC_ALG_KEM_LIGHTSABER, "round3/saber/LightSaber/PQCkemKAT_1568.rsp"),
    REG_KEM!(PQC_ALG_KEM_FIRESABER, "round3/saber/FireSaber/PQCkemKAT_3040.rsp"),
    REG_KEM!(PQC_ALG_KEM_SABER, "round3/saber/Saber/PQCkemKAT_2304.rsp"),
    REG_KEM!(PQC_ALG_KEM_HQCRMRS128, "round3/hqc/hqc-128/hqc-128_kat.rsp"),
    REG_KEM!(PQC_ALG_KEM_HQCRMRS192, "round3/hqc/hqc-192/hqc-192_kat.rsp"),
    REG_KEM!(PQC_ALG_KEM_HQCRMRS256, "round3/hqc/hqc-256/hqc-256_kat.rsp"),
    REG_KEM!(PQC_ALG_KEM_SIKE434, "round3/sike/PQCkemKAT_374.rsp"),

    // Those are Round2. KATs are very big, so skip testing until it makes sense to do so.
    //REG_SIGN!(PQC_ALG_SIG_RAINBOWVCLASSIC),
    //REG_SIGN!(PQC_ALG_SIG_RAINBOWICLASSIC),
    //REG_SIGN!(PQC_ALG_SIG_RAINBOWIIICLASSIC),
];

fn execute(kat_dir: String, thc: usize, file_filter: &str) {
    // Can't do multi-threads as DRBG context is global
    let pool = ThreadPool::new(thc);
    for k in KATS.iter() {
        let tmp = kat_dir.clone();
        if !file_filter.is_empty() && !k.kat.kat_file.contains(file_filter) {
            continue;
        }
        pool.execute(move || {
            DRBGV.lock().unwrap()
                .insert(thread::current().id(), DrbgCtx::new());
            let f = Path::new(&tmp.to_string()).join(k.kat.kat_file);
            let file = File::open(format!("{}", f.to_str().unwrap()));
            println!("Processing file: {}", Path::new(k.kat.kat_file).to_str().unwrap());
            let b = BufReader::new(file.unwrap());

            for el in KatReader::new(b, k.kat.scheme_type, k.kat.scheme_id) {
                (k.execfn)(&el);
            }
            DRBGV.lock().unwrap()
                .remove(&thread::current().id());
        });
    }
    pool.join();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut argmap = HashMap::new();

    if args.len() % 2 == 0 {
        panic!("Wrong number of arguments");
    }

    for i in (1..args.len()).step_by(2) {
        argmap.insert(&args[i], &args[i+1]);
    }

    let thread_number: usize = match argmap.get(&"--threads".to_string()) {
        Some(n) => n.to_string().parse::<usize>().unwrap(),
        None => 4 /* by default 4 threads */,
    };

    // Run only selected name of the KAT file
    let file_filter = match argmap.get(&"--filter".to_string()) {
        Some(n) => n,
        None => ""
    };

    match argmap.get(&"--katdir".to_string()) {
        Some(kat_dir) => execute(kat_dir.to_string(), thread_number, file_filter),
        None => panic!("--katdir required")
    };

}
