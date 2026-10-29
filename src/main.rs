use pq_mtls_cost::{run, Group, Pki};

fn usage() -> ! {
    eprintln!(
        "uso: pq-mtls-cost --group x25519|x25519mlkem768 [--resumption] [-n N] [--warmup W] [--label L]\n\
         Imprime una línea JSON por corrida."
    );
    std::process::exit(2)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut group, mut resumption, mut n, mut warmup, mut label) =
        (None, false, 2000u64, 50u64, String::from("none"));
    while let Some(a) = args.next() {
        match a.as_str() {
            "--group" => group = args.next().and_then(|g| Group::parse(&g)),
            "--resumption" => resumption = true,
            "-n" => {
                n = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--warmup" => {
                warmup = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--label" => label = args.next().unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }
    let group = group.unwrap_or_else(|| usage());
    let pki = Pki::generate();
    match run(&pki, group, resumption, n, warmup) {
        Ok(r) => {
            let mut v = serde_json::to_value(&r).unwrap();
            v["net"] = serde_json::Value::String(label);
            println!("{}", serde_json::to_string(&v).unwrap());
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    }
}
