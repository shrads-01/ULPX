use std::env;
use std::fs::File;
use std::io::{self, BufReader};
use std::process;
use ulpx_core::event::EventId;
use ulpx_core::framing::newline::NewlineFramer;
use ulpx_core::parser::ParserRegistry;
use ulpx_core::storage::LocalEvidenceStore;
use ulpx_infer::engine::InferenceEngine;
use ulpx_ingest::ingest_stream;
use ulpx_ir::convert::CompositeConverter;
use ulpx_mapping::engine::MappingEngine;
use ulpx_replay::interpretation::ComponentConfig;
use ulpx_replay::ReplayPipeline;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ulpx <process | replay> [args...]");
        process::exit(1);
    }

    let command = &args[1];

    let store_path = env::var("ULPX_STORE_PATH").unwrap_or_else(|_| "./.ulpx_store".to_string());

    let mut store = match LocalEvidenceStore::new(&store_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error opening evidence store at {}: {:?}", store_path, e);
            process::exit(1);
        }
    };

    let framer = NewlineFramer;

    if command == "process" {
        if args.len() != 3 {
            eprintln!("Usage: ulpx process <file | ->");
            process::exit(1);
        }
        let input_path = &args[2];
        let result = if input_path == "-" {
            let stdin = io::stdin();
            let mut handle = stdin.lock();
            ingest_stream(&mut handle, "stdin", &framer, &mut store)
        } else {
            match File::open(input_path) {
                Ok(file) => {
                    let mut reader = BufReader::new(file);
                    ingest_stream(&mut reader, input_path, &framer, &mut store)
                }
                Err(e) => {
                    eprintln!("Error opening file {}: {}", input_path, e);
                    process::exit(1);
                }
            }
        };

        match result {
            Ok(res) => {
                println!("Ingestion successful.");
                println!("Records found: {}", res.total_records);
                println!("Records stored: {}", res.stored_records);
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Ingestion failed: {}", e);
                process::exit(1);
            }
        }
    } else if command == "replay" {
        if args.len() != 3 {
            eprintln!("Usage: ulpx replay <event_id>");
            process::exit(1);
        }

        let event_id_str = &args[2];
        let event_id = match EventId::new(event_id_str.clone()) {
            Ok(id) => id,
            Err(_) => {
                eprintln!("Invalid event ID format.");
                process::exit(1);
            }
        };

        let parser_registry = ParserRegistry::new();
        let inference_engine = InferenceEngine::new();
        let ir_converter = CompositeConverter::new();
        let mapping_engine = MappingEngine::new();

        let pipeline = ReplayPipeline::new(
            &store,
            &framer,
            ComponentConfig {
                id: "NewlineFramer".into(),
                version: "1.0.0".into(),
            },
            &parser_registry,
            &inference_engine,
            &ir_converter,
            &mapping_engine,
            ComponentConfig {
                id: "DefaultMapper".into(),
                version: "1.0.0".into(),
            },
        );

        match pipeline.replay(&event_id) {
            Ok(interpretation) => {
                println!("{:#?}", interpretation);
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Replay failed: {:?}", e);
                process::exit(1);
            }
        }
    } else {
        eprintln!("Unknown command: {}", command);
        eprintln!("Usage: ulpx <process | replay> [args...]");
        process::exit(1);
    }
}
