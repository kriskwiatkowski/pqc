use katwalk::reader::{Kat, AlgType, TestVector, KatReader};
use std::{fs::File, io::BufReader};
use pqc_sys::*;
use std::env;
use std::path::Path;
use threadpool::ThreadPool;

const KAT_DIR : &'static str= ".";
type ExecFn = fn(&TestVector);
struct Register {
	kat: katwalk::reader::Kat,
	execfn: ExecFn,
}

fn signature_scheme(el: &TestVector) {

	let mut msg = Vec::new();
	msg.resize(el.sig.msg.len(), 0);
	msg.extend(el.sig.msg.iter().copied());
	unsafe {
		let p = pqc_sig_alg_by_id(el.scheme_id as u8);
		assert_eq!(
			pqc_sig_verify(p, msg.as_mut_ptr(), el.sig.msg.len() as u64,
				el.sig.sm.as_ptr(), el.sig.sm.len() as u64,
				el.sig.pk.as_ptr()), true);
	}
}

// KAT test register
const REG: [Register; 1] = [
	Register{kat:Kat{scheme_type: AlgType::AlgSignature, scheme_id: DILITHIUM2, kat_file: "round3/dilithium/dilithium2/PQCsignKAT_2544.rsp"}, execfn: signature_scheme},
];

fn execute(kat_dir: String) {
	// Can't do multi-threads as DRBG context is global
	let pool = ThreadPool::new(1);
	for k in REG.iter() {
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
