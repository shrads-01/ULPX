use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, thiserror::Error)]
pub enum ObjectStoreError {
    #[error("Invalid object key: {0}")]
    InvalidKey(String),
    #[error("Object not found: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub trait ObjectStore: Send + Sync {
    /// Writes bytes to the object store.
    /// 
    /// **Overwrite semantics**:
    /// Overwrites the object if it already exists. On Windows, this replaces the target 
    /// unless it is locked by another process (which yields an I/O error).
    ///
    /// **Atomicity guarantee**:
    /// - The payload is written fully to a temporary file in the target directory.
    /// - sync_all() is called on the temporary file to flush buffers.
    /// - The temporary file is renamed to the final key path.
    /// - A failed temporary write does not intentionally replace the existing destination.
    /// - Concurrent writes to the same key will succeed individually, but the last rename wins.
    fn put(&self, key: &str, data: &[u8]) -> Result<(), ObjectStoreError>;
    
    /// Retrieves bytes from the object store.
    fn get(&self, key: &str) -> Result<Vec<u8>, ObjectStoreError>;
    
    /// Checks if an object exists. Distinguishes between NotFound and actual filesystem errors.
    fn exists(&self, key: &str) -> Result<bool, ObjectStoreError>;
}

pub struct LocalObjectStore {
    root: PathBuf,
}

impl LocalObjectStore {
    pub fn new<P: AsRef<Path>>(root: P) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn resolve_key(&self, key: &str) -> Result<PathBuf, ObjectStoreError> {
        if key.is_empty() {
            return Err(ObjectStoreError::InvalidKey("Key cannot be empty".into()));
        }

        let path = Path::new(key);
        let mut normalized_key = PathBuf::new();

        for component in path.components() {
            match component {
                Component::Normal(c) => normalized_key.push(c),
                _ => return Err(ObjectStoreError::InvalidKey(
                    "Key contains invalid components (e.g. absolute path, parent traversal, or prefixes)".into()
                )),
            }
        }

        // Limitation: Object keys cannot lexically escape the configured root;
        // however, the implementation does not provide hostile-filesystem confinement 
        // against pre-existing symlinks or Windows reparse points.
        Ok(self.root.join(normalized_key))
    }
}

impl ObjectStore for LocalObjectStore {
    fn put(&self, key: &str, data: &[u8]) -> Result<(), ObjectStoreError> {
        let final_path = self.resolve_key(key)?;
        
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Generate a uniquely identifiable temporary file using exclusive create
        let mut attempts = 0;
        let (mut file, tmp_path) = loop {
            let count = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tid = thread::current().id();
            let pid = process::id();
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            let tmp_name = format!("tmp.{}.{}.{:?}.{}", pid, count, tid, ts);
            let tmp_path = final_path.with_extension(tmp_name);

            match OpenOptions::new().write(true).create_new(true).open(&tmp_path) {
                Ok(f) => break (f, tmp_path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    attempts += 1;
                    if attempts > 10 {
                        return Err(ObjectStoreError::Io(e));
                    }
                    continue;
                }
                Err(e) => return Err(ObjectStoreError::Io(e)),
            }
        };

        // Write to temporary file and sync
        let write_result = file.write_all(data).and_then(|_| file.sync_all());
        
        if let Err(e) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(ObjectStoreError::Io(e));
        }
        
        // Ensure file handle is closed before rename (critical for Windows)
        drop(file);

        // Atomically rename to final path (overwrites if exists on POSIX and modern Windows)
        if let Err(e) = fs::rename(&tmp_path, &final_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(ObjectStoreError::Io(e));
        }

        Ok(())
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, ObjectStoreError> {
        let path = self.resolve_key(key)?;
        match File::open(&path) {
            Ok(mut file) => {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                Ok(data)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ObjectStoreError::NotFound(key.to_string()))
            }
            Err(e) => Err(ObjectStoreError::Io(e)),
        }
    }

    fn exists(&self, key: &str) -> Result<bool, ObjectStoreError> {
        let path = self.resolve_key(key)?;
        match fs::metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(ObjectStoreError::Io(e)),
        }
    }
}