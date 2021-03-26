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
				execfn: signature_scheme}
	}
}

const KAT_DIR : &'static str= ".";
type ExecFn = fn(&TestVector);
struct Register {
	kat: katwalk::reader::Kat,
	execfn: ExecFn,
}

fn signature_scheme(el: &TestVector) {

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

// KAT test register
const KATS: &'static[Register] = &[
	REG_SIGN!(DILITHIUM2, "round3/dilithium/dilithium2/PQCsignKAT_2544.rsp"),
	REG_SIGN!(DILITHIUM3, "round3/dilithium/dilithium3/PQCsignKAT_4016.rsp"),
	REG_SIGN!(DILITHIUM5, "round3/dilithium/dilithium5/PQCsignKAT_4880.rsp"),
	//REG_SIGN!(FALCON512,  "round3/falcon/falcon512-KAT.rsp"),
	//REG_SIGN!(FALCON1024, "round3/falcon/falcon1024-KAT.rsp"),
	//REG_SIGN!(RAINBOWVCLASSIC),
    //REG_SIGN!(RAINBOWICLASSIC),
    //REG_SIGN!(RAINBOWIIICLASSIC),

    // Some implementations of sphincs are for round3
    REG_SIGN!(SPHINCSSHA256192FSIMPLE,"round3/sphincs/sphincs-sha256-192f-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHA256192FROBUST,"round3/sphincs/sphincs-sha256-192f-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHA256256SSIMPLE,"round3/sphincs/sphincs-sha256-256s-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHA256256SROBUST,"round3/sphincs/sphincs-sha256-256s-robust/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHAKE256192FROBUST,"round3/sphincs/sphincs-shake256-192f-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHAKE256192FSIMPLE,"round3/sphincs/sphincs-shake256-192f-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHAKE256256SSIMPLE,"round3/sphincs/sphincs-shake256-256s-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHAKE256256SROBUST,"round3/sphincs/sphincs-shake256-256s-robust/PQCsignKAT_128.rsp"),

    // And some for round 2
    REG_SIGN!(SPHINCSSHA256128SSIMPLE,"round2/sphincs/sphincs-sha256-128s-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHA256128SROBUST,"round2/sphincs/sphincs-sha256-128s-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHA256128FSIMPLE,"round2/sphincs/sphincs-sha256-128f-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHA256128FROBUST,"round2/sphincs/sphincs-sha256-128f-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHA256192SSIMPLE,"round2/sphincs/sphincs-sha256-192s-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHA256192SROBUST,"round2/sphincs/sphincs-sha256-192s-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHA256256FROBUST,"round2/sphincs/sphincs-sha256-256f-robust/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHA256256FSIMPLE,"round2/sphincs/sphincs-sha256-256f-simple/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHAKE256128FSIMPLE,"round2/sphincs/sphincs-shake256-128f-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHAKE256128SSIMPLE,"round2/sphincs/sphincs-shake256-128s-simple/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHAKE256128FROBUST,"round2/sphincs/sphincs-shake256-128f-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHAKE256128SROBUST,"round2/sphincs/sphincs-shake256-128s-robust/PQCsignKAT_64.rsp"),
    REG_SIGN!(SPHINCSSHAKE256192SSIMPLE,"round2/sphincs/sphincs-shake256-192s-simple/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHAKE256192SROBUST,"round2/sphincs/sphincs-shake256-192s-robust/PQCsignKAT_96.rsp"),
    REG_SIGN!(SPHINCSSHAKE256256FROBUST,"round2/sphincs/sphincs-shake256-256f-robust/PQCsignKAT_128.rsp"),
    REG_SIGN!(SPHINCSSHAKE256256FSIMPLE,"round2/sphincs/sphincs-shake256-256f-simple/PQCsignKAT_128.rsp"),
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
