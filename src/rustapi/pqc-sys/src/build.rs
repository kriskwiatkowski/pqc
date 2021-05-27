extern crate cmake;
use cmake::Config;
extern crate bindgen;

fn main() {
	let dst = Config::new("../../../")
		.profile("Debug")
		.very_verbose(true)
        .build();

	println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=pqc_s");
    // For some reason GetX86Info symbol is undefined in the pqc_s. Hence this line
    println!("cargo:rustc-link-lib=static=cpu_features");
    println!("cargo:rerun-if-changed=../../../capi/*,../../../kem/*,../../../sign/*,../../../../public/pqc/pqc.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("../../../public/pqc/pqc.h")
        // Don't define randombytes()
        .clang_arg("-DPQC_WEAK_RANDOMBYTES")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Add "Default" whenever possible
        .derive_default(true)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");
    bindings
    	.write_to_file("src/bindings.rs")
    	.expect("Couldn't write bindings");
}
