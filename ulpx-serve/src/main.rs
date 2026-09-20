use std::env;
use std::sync::Arc;
use tokio::net::TcpListener;
use ulpx_core::storage::{EvidenceStore, LocalEvidenceStore};
use ulpx_serve::create_router;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store_path = env::var("ULPX_STORE_PATH").unwrap_or_else(|_| "./.ulpx_store".to_string());
    let serve_addr = env::var("ULPX_SERVE_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    println!("ULPX Serve starting...");

    let absolute_store_path = env::current_dir()
        .map(|cwd| cwd.join(&store_path))
        .unwrap_or_else(|_| std::path::PathBuf::from(&store_path));

    println!(
        "Store path: {} (Absolute: {})",
        store_path,
        absolute_store_path.display()
    );
    println!("Bind address: {}", serve_addr);

    let store = LocalEvidenceStore::new(&store_path)
        .map_err(|e| format!("Failed to open evidence store at '{}': {}", store_path, e))?;

    let event_count = store.list_events(0, usize::MAX).len();
    println!("Loaded {} events from store.", event_count);

    if event_count == 0 {
        println!("WARNING: The evidence store is completely empty.");
        println!("If you recently ingested events, ensure ulpx-serve is running from the same");
        println!("current working directory as ulpx-ingest, or set ULPX_STORE_PATH explicitly.");
    }

    let app = create_router(Arc::new(store), store_path.clone());

    let listener = TcpListener::bind(&serve_addr)
        .await
        .map_err(|e| format!("Failed to bind to '{}': {}", serve_addr, e))?;

    println!("Listening on http://{}", serve_addr);
    println!("Access the ULPX Analyst UI at http://{}", serve_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
