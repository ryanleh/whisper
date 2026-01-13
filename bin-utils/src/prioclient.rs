use crate::AggFunc;
use clap::{Arg, Command};
use common::hpke::PublicKey;
use serde_json::Value;

pub struct Options {
    pub alice: String,
    pub bob: String,
    pub num_clients: usize,
    pub num_bad_clients: u64,
    pub agg_fn: AggFunc,
    pub vec_size: u32,
    pub bitlength: u32,
    pub log_level: tracing_core::Level,
    /// Optional HPKE public key for encrypting messages to Alice
    pub alice_pk: Option<PublicKey>,
    /// Optional HPKE public key for encrypting messages to Bob
    pub bob_pk: Option<PublicKey>,
}

impl Options {
    pub fn load_from_json(program_name: &str) -> Self {
        let matches = Command::new(program_name)
            .version("0.1")
            .arg(
                Arg::new("config")
                    .short('c')
                    .long("config")
                    .required(true)
                    .takes_value(true)
                    .help("json to get the client config"),
            )
            .get_matches();

        let filename = matches.value_of("config").unwrap();

        let json_data = &std::fs::read_to_string(filename).expect("Cannot open JSON file");
        let v: Value = serde_json::from_str(json_data).expect("Cannot parse JSON config");

        let alice = v["alice"].as_str().expect("Can't parse alice ip");
        let bob = v["bob"].as_str().expect("Can't parse bob ip");
        let num_clients = v["num_clients"].as_u64().expect("Can't parse num_clients") as usize;
        let num_bad_clients = v["num_bad_clients"]
            .as_u64()
            .expect("Can't parse num_bad_clients");
        let agg_fn = match v["agg_fn"].as_str().expect("Can't parse agg_fn") {
            "sv" => AggFunc::SumVec,
            "hs" => AggFunc::Average,
            "av" => AggFunc::Average,
            _ => panic!("Invalid aggregation function"),
        };
        let vec_size = v["vec_size"].as_u64().expect("Can't parse vec_size") as u32;
        let bitlength = v["bitlength"].as_u64().expect("Can't parse bitlength") as u32;

        let log_level = match v["log_level"].as_str() {
            Some("debug") => tracing_core::Level::DEBUG,
            Some("info") => tracing_core::Level::INFO,
            Some("warn") => tracing_core::Level::WARN,
            Some("error") => tracing_core::Level::ERROR,
            _ => panic!("Invalid log level"),
        };

        // Load optional HPKE public keys for servers
        let alice_pk = v["alice_pk_path"]
            .as_str()
            .map(|path| PublicKey::read_from_file(path).expect("Failed to read Alice's public key"));
        let bob_pk = v["bob_pk_path"]
            .as_str()
            .map(|path| PublicKey::read_from_file(path).expect("Failed to read Bob's public key"));

        Options {
            alice: alice.to_string(),
            bob: bob.to_string(),
            num_clients,
            num_bad_clients,
            log_level,
            agg_fn,
            vec_size,
            bitlength,
            alice_pk,
            bob_pk,
        }
    }
}
