fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:5223".into());
    if let Err(e) = smp_rs::server::run(&addr) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
