//! Layer 4: Cryptographic State Gatekeeper
//!
//! Enforces empirical ground-truth invariants on tool execution:
//! - Cryptographic SHA-256 + Inode filesystem delta anchoring (Zero Ghost Actions).
//! - Non-zero exit code and masked error interception (Zero Masked Failures).
//! - Exact circular loop detection via action signature hashing.

use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub exists: bool,
    pub inode: u64,
    pub mtime_ns: i64,
    pub size: u64,
    pub sha256: String,
}

pub struct CryptographicGatekeeper {
    pub root_dir: PathBuf,
    action_history: Vec<String>,
    loop_window: usize,
}

impl CryptographicGatekeeper {
    pub fn new<P: AsRef<Path>>(root_dir: P) -> Self {
        Self {
            root_dir: root_dir.as_ref().to_path_buf(),
            action_history: Vec::new(),
            loop_window: 6,
        }
    }

    pub fn compute_fingerprint<P: AsRef<Path>>(&self, file_path: P) -> FileSnapshot {
        let p = if file_path.as_ref().is_absolute() {
            file_path.as_ref().to_path_buf()
        } else {
            self.root_dir.join(file_path.as_ref())
        };

        if !p.exists() || !p.is_file() {
            return FileSnapshot {
                path: p,
                exists: false,
                inode: 0,
                mtime_ns: 0,
                size: 0,
                sha256: String::new(),
            };
        }

        let metadata = match fs::metadata(&p) {
            Ok(m) => m,
            Err(_) => {
                return FileSnapshot {
                    path: p,
                    exists: true,
                    inode: 0,
                    mtime_ns: 0,
                    size: 0,
                    sha256: "IO_ERROR".to_string(),
                };
            }
        };

        // Security check: Protect against FIFOs, sockets, device files that block indefinitely
        if !metadata.file_type().is_file() {
            return FileSnapshot {
                path: p,
                exists: true,
                inode: metadata.ino(),
                mtime_ns: metadata.mtime_nsec(),
                size: metadata.size(),
                sha256: "SPECIAL_FILE_NOT_HASHED".to_string(),
            };
        }

        // Security check: Cap maximum hashable size to 100MB to prevent DoS on giant binaries
        const MAX_HASHABLE_BYTES: u64 = 100 * 1024 * 1024;
        if metadata.size() > MAX_HASHABLE_BYTES {
            return FileSnapshot {
                path: p,
                exists: true,
                inode: metadata.ino(),
                mtime_ns: metadata.mtime_nsec(),
                size: metadata.size(),
                sha256: format!("SIZE_EXCEEDS_MAX_HASHABLE_{}", metadata.size()),
            };
        }

        let mut hasher = Sha256::new();
        let sha = match File::open(&p) {
            Ok(mut f) => {
                let mut buffer = [0u8; 65536];
                loop {
                    match f.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => hasher.update(&buffer[..n]),
                        Err(_) => return FileSnapshot {
                            path: p,
                            exists: true,
                            inode: metadata.ino(),
                            mtime_ns: metadata.mtime_nsec(),
                            size: metadata.size(),
                            sha256: "READ_ERROR".to_string(),
                        },
                    }
                }
                format!("{:x}", hasher.finalize())
            }
            Err(_) => "OPEN_ERROR".to_string(),
        };

        FileSnapshot {
            path: p,
            exists: true,
            inode: metadata.ino(),
            mtime_ns: metadata.mtime_nsec(),
            size: metadata.size(),
            sha256: sha,
        }
    }

    pub fn verify_file_mutation(
        &self,
        file_path: &Path,
        pre_snapshot: &FileSnapshot,
        claim_type: &str,
    ) -> (bool, String, Option<FileSnapshot>) {
        let post = self.compute_fingerprint(file_path);

        match claim_type {
            "create" | "write" => {
                if !post.exists {
                    return (
                        false,
                        format!("FAULT_EPISTEMIC_MISMATCH: File '{:?}' claimed created, but does not exist on disk.", file_path),
                        Some(post),
                    );
                }
                if pre_snapshot.exists && pre_snapshot.sha256 == post.sha256 {
                    let short_sha = if post.sha256.len() >= 8 { &post.sha256[..8] } else { &post.sha256 };
                    return (
                        false,
                        format!("FAULT_EPISTEMIC_MISMATCH: File '{:?}' claimed overwritten, but SHA-256 hash was completely identical ({}).", file_path, short_sha),
                        Some(post),
                    );
                }
                (true, "VERIFIED_FILE_CREATED_OR_OVERWRITTEN".to_string(), Some(post))
            }
            "edit" | "modify" => {
                if !post.exists {
                    return (
                        false,
                        format!("FAULT_EPISTEMIC_MISMATCH: File '{:?}' claimed modified, but was deleted or missing.", file_path),
                        Some(post),
                    );
                }
                if !pre_snapshot.exists {
                    return (true, "VERIFIED_FILE_NEWLY_CREATED".to_string(), Some(post));
                }
                if pre_snapshot.sha256 == post.sha256 {
                    let short_sha = if post.sha256.len() >= 8 { &post.sha256[..8] } else { &post.sha256 };
                    return (
                        false,
                        format!("FAULT_EPISTEMIC_MISMATCH: File '{:?}' claimed edited, but SHA-256 was unchanged ({}). Zero disk mutation.", file_path, short_sha),
                        Some(post),
                    );
                }
                (true, "VERIFIED_FILE_MUTATED".to_string(), Some(post))
            }
            "delete" => {
                if post.exists {
                    return (
                        false,
                        format!("FAULT_EPISTEMIC_MISMATCH: File '{:?}' claimed deleted, but still exists on disk.", file_path),
                        Some(post),
                    );
                }
                (true, "VERIFIED_FILE_DELETED".to_string(), Some(post))
            }
            _ => (true, "UNKNOWN_CLAIM_TYPE_PASSED".to_string(), Some(post)),
        }
    }

    pub fn verify_execution_outcome(
        &self,
        command: &str,
        exit_code: i32,
        claimed_success: bool,
    ) -> (bool, String) {
        if claimed_success && exit_code != 0 {
            return (
                false,
                format!("FAULT_MASKED_FAILURE: Agent claimed command '{}' succeeded, but process exited with non-zero exit code {}.", command, exit_code),
            );
        }
        (true, "VERIFIED_EXECUTION_OUTCOME".to_string())
    }

    pub fn check_circular_loop(
        &mut self,
        tool_name: &str,
        payload: &str,
        exit_code: i32,
    ) -> (bool, String) {
        let clean_payload: String = payload.chars().filter(|c| !c.is_control()).take(200).collect();
        let sig = format!("{}:{}:{}", tool_name, exit_code, clean_payload.trim());

        self.action_history.push(sig.clone());
        if self.action_history.len() > 50 {
            self.action_history.remove(0);
        }

        let start = self.action_history.len().saturating_sub(self.loop_window);
        let window = &self.action_history[start..];
        let occurrences = window.iter().filter(|s| **s == sig).count();

        if occurrences >= 3 {
            return (
                true,
                format!(
                    "FAULT_CIRCULAR_LOOP_DETECTED: Agent invoked '{}' with identical payload 3 times in last {} turns. Forcing dead-end registration.",
                    tool_name, self.loop_window
                ),
            );
        }

        (false, "NO_LOOP_DETECTED".to_string())
    }
}
