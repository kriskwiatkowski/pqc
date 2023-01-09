use katwalk::reader::{Kat, AlgType, TestVector, KatReader};
use std::{fs::File, io::BufReader};
use pqc_sys::*;
use std::env;
use std::path::Path;
use threadpool::ThreadPool;
use std::convert::TryInto;
use aes_ctr_drbg::DrbgCtx as AesCtrDrbgCtx;
use std::collections::HashMap;
use std::thread;
use std::sync::Mutex;
use lazy_static::lazy_static;

#[derive(PartialEq)]
enum TestStatus {
    Processed,
    // For now this variant is not used
    #[allow(dead_code)]
    Skipped,
}

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
// Needed to implement get_rng.
trait Rng {
    fn init(&mut self, entropy: &[u8], diversifier: Vec<u8>);
    fn get_random(&mut self, data: &mut [u8]);
}

// DummyDrbg just returns value of self.data. Useful
// in testing functions that are non-deterministic.
struct DummyDrbgContext{
    data: Vec<u8>,
}

impl Rng for DummyDrbgContext {
    fn init(&mut self, entropy: &[u8], _diversifier: Vec<u8>) {
        self.data = entropy.to_vec();
    }
    fn get_random(&mut self, data: &mut [u8]) {
        for i in 0..std::cmp::min(data.len(), self.data.len()) {
            data[i] = self.data[i];
        }
    }
}

// DrbgCtx uses AES-CTR to generate random byte-string.
impl Rng for AesCtrDrbgCtx {
    fn init(&mut self, entropy: &[u8], diversifier: Vec<u8>) {
        self.init(entropy, diversifier);
    }
    fn get_random(&mut self, data: &mut [u8]) {
        self.get_random(data);
    }
}

// Allows to use some custom Drbg that implements
// Rng trait. In Current implementation if `use_aes`
// is set then AesCtrDrbgCtx is used (default), otherwise
// DummyDrbg is used.
struct CustomizableDrbgCtx{
    aes_drbg: AesCtrDrbgCtx,
    dummy: DummyDrbgContext,
    use_aes: bool,
}

impl CustomizableDrbgCtx{
    pub const fn new() -> Self {
        Self {
            use_aes: true,
            aes_drbg: AesCtrDrbgCtx::new(),
            dummy: DummyDrbgContext{
                data: Vec::new(),
            },
        }
    }

    // TODO: possibily to be done with Box<> or something
    fn get_rng(&mut self) -> &mut dyn Rng {
        if self.use_aes {
            return &mut self.aes_drbg;
        } else {
            return &mut self.dummy;
        }
    }

    pub fn init(&mut self, entropy: &[u8], diversifier: Vec<u8>, is_fixed: bool) {
        if is_fixed {
            self.use_aes = false;
        }
        self.get_rng().init(entropy, diversifier);
    }

    pub fn get_random(&mut self, data: &mut [u8]) {
        self.get_rng().get_random(data);
    }
}

// Stores one DRBG context per execution thread. DRBG
// is inserted in this map, just after thread starts
// and removed after thread is finished. Operation
// is synchronized.
lazy_static! {
    static ref DRBGV: Mutex<
        HashMap<thread::ThreadId, CustomizableDrbgCtx>> = Mutex::new(HashMap::new());
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

type ExecFn = fn(&TestVector) -> TestStatus;
struct Register {
    kat: katwalk::reader::Kat,
    execfn: ExecFn,
}

fn test_sign_vector(el: &TestVector) -> TestStatus {
    let mut pk = Vec::new();
    let mut sk = Vec::new();
    let mut sm = Vec::new();

    if let Some(drbg) = DRBGV.lock().unwrap().get_mut(&thread::current().id()) {
        drbg.init(el.sig.seed.as_slice(), Vec::new(), false);
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
        return TestStatus::Processed;
    }
}

fn test_kem_vector(el: &TestVector) -> TestStatus {
    let mut pk = Vec::new();
    let mut sk = Vec::new();
    let mut ct = Vec::new();
    let mut ss = Vec::new();

    if let Some(drbg) = DRBGV.lock().unwrap().get_mut(&thread::current().id()) {
        drbg.init(el.kem.seed.as_slice(), Vec::new(), false);
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
    return TestStatus::Processed;
}

// KAT test register
const KATS: &'static[Register] = &[
    REG_SIGN!(PQC_ALG_SIG_DILITHIUM2, "pqshield/dilithium/dilithium2/nist.kat"),
    REG_SIGN!(PQC_ALG_SIG_DILITHIUM3, "pqshield/dilithium/dilithium3/nist.kat"),
    REG_SIGN!(PQC_ALG_SIG_DILITHIUM5, "pqshield/dilithium/dilithium5/nist.kat"),
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
    REG_KEM!(PQC_ALG_KEM_KYBER768, "round3/kyber/kyber768/PQCkemKAT_2400.rsp"),
    REG_KEM!(PQC_ALG_KEM_KYBER1024, "round3/kyber/kyber1024/PQCkemKAT_3168.rsp"),
    REG_KEM!(PQC_ALG_KEM_KYBER512, "round3/kyber/kyber512/PQCkemKAT_1632.rsp"),
    REG_KEM!(PQC_ALG_KEM_HQCRMRS128, "round3/hqc/hqc-128/hqc-128_kat.rsp"),
    REG_KEM!(PQC_ALG_KEM_HQCRMRS192, "round3/hqc/hqc-192/hqc-192_kat.rsp"),
    REG_KEM!(PQC_ALG_KEM_HQCRMRS256, "round3/hqc/hqc-256/hqc-256_kat.rsp"),
];

// Main loop
fn execute(kat_dir: String, thc: usize, file_filter: &str) -> u8 {
    // Can't do multi-threads as DRBG context is global
    let pool = ThreadPool::new(thc);
    let path = Path::new(&kat_dir);
    let mut code: u8 = 0;

    for k in KATS.iter() {
        if !file_filter.is_empty() && !k.kat.kat_file.contains(file_filter) {
            continue;
        }

        // Check if file exists
        let filepath = path.join(k.kat.kat_file);
        let fhandle = match File::open(filepath) {
            Ok(fhandle) => fhandle,
            Err(_) => {
                eprintln!("File {:?} doesn't exist", k.kat.kat_file);
                code |= 1;
                continue;
            }
        };
        let buf = BufReader::new(fhandle);

        pool.execute(move || {
            DRBGV.lock().unwrap()
                .insert(thread::current().id(), CustomizableDrbgCtx::new());
            let proc = KatReader::new(buf, k.kat.scheme_type, k.kat.scheme_id);
            let iter = proc.into_iter();
            let mut processed = 0;
            let mut skipped = 0;
            for el in iter {
                let status = (k.execfn)(&el);
                match status {
                    TestStatus::Processed => processed += 1,
                    TestStatus::Skipped   => skipped += 1,
                }
            }
            println!("{:60} KAT# : {:10}{:10}", k.kat.kat_file, processed,skipped);
            DRBGV.lock().unwrap().remove(&thread::current().id());
        });
    }
    pool.join();
    return code;
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

    // Number of threads to be used
    let thread_number: usize = match argmap.get(&"--threads".to_string()) {
        Some(n) => n.to_string().parse::<usize>().unwrap(),
        None => 4 /* by default 4 threads */,
    };

    // Run only selected name of the KAT file
    let file_filter = match argmap.get(&"--filter".to_string()) {
        Some(n) => n,
        None => ""
    };

    // Header for the results
    println!("Test file{:60}Processed   Skipped", "");
    println!("------------------------------------------------------------------------------------------");
    match argmap.get(&"--katdir".to_string()) {
        Some(kat_dir) =>
            std::process::exit(
                execute(kat_dir.to_string(), thread_number, file_filter).into()),
        None => panic!("--katdir required")
    };

}
