use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use rand::Rng;

// Import the necessary modules from the server-batch-prio3 crate
use server_batch_prio3::*;
use prio::vdaf::prio3::optimal_chunk_length;

// Generate real VDAF keys using the Prio3 library
fn generate_vdaf_keys(num_clients: usize, vec_size: usize, bitlength: usize) -> Vec<Vec<u8>> {
    let chunk_size = optimal_chunk_length(vec_size);
    let vdaf = Prio3::new_sum_vec_256(2, bitlength, vec_size, chunk_size).unwrap();
    let mut rng = rand::thread_rng();
    
    (0..num_clients)
        .map(|_| {
            // Generate a random input for each client
            let input = (0..vec_size).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            
            // Generate VDAF keys using the library
            let (public_share, input_shares) = vdaf.shard(&input, &()).unwrap();
            
            // Encode the input shares for transmission
            let mut encoded_keys = Vec::new();
            for share in input_shares {
                encoded_keys.extend(share.get_encoded());
            }
            encoded_keys
        })
        .collect()
}

fn run_benchmark(num_clients: usize, vec_size: usize, bitlength: usize) -> (Duration, usize, usize, usize) {
    let runtime = Runtime::new().unwrap();
    
    let chunk_size = optimal_chunk_length(vec_size);
    println!("Benchmarking: {} clients, vec_size={}, bitlength={}, chunk_size={} (optimal)", 
             num_clients, vec_size, bitlength, chunk_size);
    
    let vdaf_keys = generate_vdaf_keys(num_clients, vec_size, bitlength);
    let verify_key = [0u8; 16];
    
    let start = Instant::now();
    
    let result = runtime.block_on(async {
        // Create the actual Prio3 VDAF instance
        let vdaf = Prio3::new_sum_vec_256(2, bitlength, vec_size, chunk_size).unwrap();
        
        // Create Prio3Gadgets with SumVec
        let prio3_gadgets = Prio3Gadgets {
            prio3sv: Some(vdaf),
            prio3hist: None,
            prio3avg: None,
        };
        
        // Create a mock peer connection for benchmarking
        let peer = MpcConnection::new_as_alice(7777, 1).await;
        let mut peer_idgen = IdGen::new();
        
        // Call the actual server function
        let (agg_share, comm_bytes, clients_passed, verif_time) = 
            run_vdaf_prepare_rayon(
                prio3_gadgets,
                verify_key,
                vdaf_keys,
                peer,
                0, // num_bad_clients = 0
                peer_idgen,
                AggFunc::SumVec,
            ).await.unwrap();
        
        (verif_time, comm_bytes, clients_passed, chunk_size)
    });
    
    let total_time = start.elapsed();
    let (verif_time, comm_bytes, clients_passed, chunk_size) = result;
    
    (total_time, comm_bytes, clients_passed, chunk_size)
}

fn main() {
    println!("Server-Batch-Prio3 SumVec Benchmarks");
    println!("=====================================");
    
    let test_configs = vec![
        (100, 128, 16),
        (1000, 128, 16),
        (10000, 128, 16),
        (1000, 256, 16),
        (1000, 512, 16),
        (1000, 128, 8),
        (1000, 128, 32),
    ];
    
    println!("\nResults:");
    println!("{:<10} {:<10} {:<10} {:<10} {:<15} {:<15} {:<15}", 
             "Clients", "Vec Size", "Bitlength", "Chunk Size", "Total Time (ms)", "Verif Time (ms)", "Comm (MB)");
    println!("{:-<90}", "");
    
    for (num_clients, vec_size, bitlength) in test_configs {
        let (total_time, comm_bytes, clients_passed, chunk_size) = run_benchmark(num_clients, vec_size, bitlength);
        
        let total_ms = total_time.as_millis();
        let comm_mb = comm_bytes as f64 / (1024.0 * 1024.0);
        
        println!("{:<10} {:<10} {:<10} {:<10} {:<15} {:<15} {:<15.2}", 
                 num_clients, vec_size, bitlength, chunk_size, total_ms, "N/A", comm_mb);
    }
    
    println!("\nBenchmarking completed!");
} 