use std::collections::HashSet;
use std::time::Instant;

use bin_utils::prioclient::Options;
use bin_utils::AggFunc;
use bin_utils::Prio3Gadgets;
use bin_utils::SumVecType;
use bridge::{client_server::batch_meta_clients, id_tracker::IdGen};
use futures::stream::FuturesUnordered;
use prio::codec::Encode;
use prio::field::Field128;
use prio::field::FieldElement;
use prio::vdaf::prio3::Prio3;
use prio::vdaf::BatchClient;
use prio::vdaf::{xof::XofShake128, VdafBatchedKey};
use rand::seq::IteratorRandom;
use rand::Rng;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use serialize::UseSerde;

use tracing::info;
const NUM_CORES: usize = 32;

#[tokio::main]
pub async fn main() {
    let options = Options::load_from_json("SV2 Client");

    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(options.log_level)
        .init();

    let prio3_len = options.vec_size as usize;
    // Auto-compute optimal chunk size from bitlength and vec_size
    let prio3_chunk_len = prio::vdaf::prio3::optimal_chunk_length((options.bitlength * options.vec_size) as usize);
    println!("No. of bad clients d = {}", options.num_bad_clients);

    let mut rng = rand::thread_rng();

    let prio3: Prio3Gadgets = Prio3Gadgets::new(&options.agg_fn, prio3_len, prio3_chunk_len);

    let bad_clients = HashSet::<usize>::from_iter(
        (0..options.num_clients)
            .choose_multiple(&mut rng, options.num_bad_clients as usize)
            .iter()
            .cloned(),
    );

    // Instead of having each client open up a new connection, we send num_clients/32 keys at a time.

    let conns = batch_meta_clients(NUM_CORES, 0, &options.alice, &options.bob).await;

    let handles = FuturesUnordered::new();

    // Start timing for encoding
    let encoding_start = Instant::now();

    let all_keys = (0..NUM_CORES)
        .into_par_iter()
        .map(|i| {
            let mut rng = rand::thread_rng();
            let num_to_send = if i == NUM_CORES - 1 {
                options.num_clients - (NUM_CORES - 1) * (options.num_clients / NUM_CORES)
            } else {
                options.num_clients / NUM_CORES
            };

            let begin = i * (options.num_clients / NUM_CORES);
            let end = begin + num_to_send;

            let (alice_keys, bob_keys): (Vec<_>, Vec<_>) = (begin..end)
                .map(|cl_id| {
                    let nonce: [u8; 16] = rng.gen();
                    let (
                        public_share,
                        input_shares_0,
                        input_shares_1,
                        public_share_second,
                        public_proof_0,
                        public_proof_1,
                        blinds,
                    ) = match options.agg_fn {
                        AggFunc::SumVec => {
                            let measurement = (0..prio3_len)
                                .map(|_| rng.gen::<u16>() as u128)
                                .collect::<Vec<_>>();

                            prio3
                                .prio3sv
                                .as_ref()
                                .unwrap()
                                .shard_batched(&measurement, &nonce)
                                .unwrap()
                        }
                        AggFunc::Histogram => {
                            let measurement = (rng.gen::<u16>() % prio3_len as u16) as usize;
                            prio3
                                .prio3hist
                                .as_ref()
                                .unwrap()
                                .shard_batched(&measurement, &nonce)
                                .unwrap()
                        }
                        AggFunc::Average => {
                            let measurement = rng.gen::<u16>() as u128;
                            prio3
                                .prio3avg
                                .as_ref()
                                .unwrap()
                                .shard_batched(&measurement, &nonce)
                                .unwrap()
                        }
                    };

                    let num_queries =
                        public_proof_0.encoded_len().unwrap() / Field128::ENCODED_SIZE;

                    let alice_id = if i & 1 == 0 { 0 } else { 1 };
                    let bob_id = 1 - alice_id;

                    // Using SumVecType here rather than Hist or Avg is fine; doesn't matter
                    let alice_key = VdafBatchedKey::<Prio3<SumVecType, XofShake128, 16>> {
                        client_id: cl_id as u128,
                        public_share: public_share.clone(),
                        agg_id: alice_id as u8,
                        input_share_0: input_shares_0[alice_id].clone(),
                        input_share_1: input_shares_1[alice_id].clone(),
                        public_share_second: public_share_second.clone(),
                        num_queries,
                        public_proof_0: public_proof_0.clone(),
                        public_proof_1: public_proof_1.clone(),
                        query_rand_blinds: blinds[alice_id].clone(),
                        nonce: nonce.clone(),
                    };

                    let mut bob_key = VdafBatchedKey::<Prio3<SumVecType, XofShake128, 16>> {
                        client_id: cl_id as u128,
                        public_share: public_share.clone(),
                        agg_id: bob_id as u8,
                        input_share_0: input_shares_0[bob_id].clone(),
                        input_share_1: input_shares_1[bob_id].clone(),
                        public_share_second: public_share_second.clone(),
                        num_queries,
                        public_proof_0: public_proof_0.clone(),
                        public_proof_1: public_proof_1.clone(),
                        query_rand_blinds: blinds[bob_id].clone(),
                        nonce: nonce.clone(),
                    };

                    if bad_clients.contains(&cl_id) {
                        // tamper the keys
                        bob_key.nonce[0] += 1u8;
                    }

                    (alice_key.get_encoded(), bob_key.get_encoded())
                })
                .unzip();
            (alice_keys, bob_keys)
        })
        .collect::<Vec<_>>();

    let total_encoding_time = encoding_start.elapsed();
    let total_keys_generated = options.num_clients;
    let avg_encoding_time = total_encoding_time.as_micros() as f64 / total_keys_generated as f64;

    // Calculate total encoding sizes
    let total_alice_size: usize = all_keys.iter().map(|(alice_keys, _)| alice_keys.iter().map(|key| key.len()).sum::<usize>()).sum();
    let total_bob_size: usize = all_keys.iter().map(|(_, bob_keys)| bob_keys.iter().map(|key| key.len()).sum::<usize>()).sum();
    let avg_alice_size = total_alice_size as f64 / total_keys_generated as f64;
    let avg_bob_size = total_bob_size as f64 / total_keys_generated as f64;

    for (i, (alice, bob)) in conns.iter().enumerate() {
        let mut alice_idgen = IdGen::new();
        let mut bob_idgen = IdGen::new();
        handles.push(
            alice
                .send_message(alice_idgen.next_send_id(), UseSerde(all_keys[i].0.clone()))
                .unwrap(),
        );
        handles.push(
            bob.send_message(bob_idgen.next_send_id(), UseSerde(all_keys[i].1.clone()))
                .unwrap(),
        );

        info!("sent id {}", i);
    }

    for h in handles {
        h.await.unwrap();
    }
    
    println!("CLIENT-BATCH-PRIO3 ENCODING METRICS:");
    println!("Total clients: {}", total_keys_generated);
    println!("Total encoding time: {:.2} ms", total_encoding_time.as_millis());
    println!("Average encoding time per client: {:.2} μs", avg_encoding_time);
    println!("Helper (Alice) encoding size: {:.0} bytes avg, {} bytes total", avg_alice_size, total_alice_size);
    println!("Leader (Bob) encoding size: {:.0} bytes avg, {} bytes total", avg_bob_size, total_bob_size);
    info!("Generated keys");
}
