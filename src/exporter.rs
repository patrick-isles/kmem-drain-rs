//! Prometheus Metrics Exporter on :9109/metrics
//!
//! Exposes kernel slab allocations, zombie IPC shared memory, and compaction stalls.

use crate::shm_reaper::ShmSegment;
use crate::slab_scanner::KernelMemoryState;
use std::sync::{Arc, RwLock};
use std::thread;
use tiny_http::{Response, Server};

#[derive(Debug, Clone)]
pub struct KmemSnapshot {
    pub kernel_mem: KernelMemoryState,
    pub shm_segments: Vec<ShmSegment>,
    pub posix_shm_files: usize,
    pub posix_shm_bytes: u64,
}

pub struct KmemExporter;

impl KmemExporter {
    pub fn start_exporter(state: Arc<RwLock<KmemSnapshot>>, port: u16) {
        thread::spawn(move || {
            let addr = format!("0.0.0.0:{}", port);
            let server = match Server::http(&addr) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Prometheus HTTP server failed to bind to {}: {}", addr, e);
                    return;
                }
            };

            for request in server.incoming_requests() {
                if request.url() == "/metrics" || request.url() == "/" {
                    let snapshot = state.read().unwrap().clone();

                    let mut body = String::with_capacity(2048);
                    body.push_str("# HELP kmem_slab_unreclaimable_bytes Kernel memory trapped in unreclaimable slab caches\n");
                    body.push_str("# TYPE kmem_slab_unreclaimable_bytes gauge\n");
                    body.push_str(&format!(
                        "kmem_slab_unreclaimable_bytes {}\n",
                        snapshot.kernel_mem.slab_unreclaimable_kb * 1024
                    ));

                    body.push_str("# HELP kmem_slab_reclaimable_bytes Kernel memory in reclaimable slab caches (dentries, inodes)\n");
                    body.push_str("# TYPE kmem_slab_reclaimable_bytes gauge\n");
                    body.push_str(&format!(
                        "kmem_slab_reclaimable_bytes {}\n",
                        snapshot.kernel_mem.slab_reclaimable_kb * 1024
                    ));

                    body.push_str("# HELP kmem_direct_compaction_stalls_total Direct memory compaction stalls causing latency spikes\n");
                    body.push_str("# TYPE kmem_direct_compaction_stalls_total counter\n");
                    body.push_str(&format!(
                        "kmem_direct_compaction_stalls_total {}\n",
                        snapshot.kernel_mem.direct_compaction_stalls
                    ));

                    let orphan_bytes: u64 = snapshot
                        .shm_segments
                        .iter()
                        .filter(|s| s.is_zombie_orphan)
                        .map(|s| s.size_bytes)
                        .sum();

                    body.push_str("# HELP kmem_zombie_shm_bytes_total Total leaked shared memory trapped in orphaned unattached segments\n");
                    body.push_str("# TYPE kmem_zombie_shm_bytes_total gauge\n");
                    body.push_str(&format!("kmem_zombie_shm_bytes_total {}\n", orphan_bytes));

                    let orphan_count = snapshot.shm_segments.iter().filter(|s| s.is_zombie_orphan).count();
                    body.push_str("# HELP kmem_zombie_shm_segments_count Number of dead-PID unattached shared memory segments\n");
                    body.push_str("# TYPE kmem_zombie_shm_segments_count gauge\n");
                    body.push_str(&format!("kmem_zombie_shm_segments_count {}\n", orphan_count));

                    body.push_str("# HELP kmem_posix_shm_bytes_total Total bytes occupied in /dev/shm tmpfs\n");
                    body.push_str("# TYPE kmem_posix_shm_bytes_total gauge\n");
                    body.push_str(&format!("kmem_posix_shm_bytes_total {}\n", snapshot.posix_shm_bytes));

                    let response = Response::from_string(body)
                        .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/plain; version=0.0.4"[..]).unwrap());
                    let _ = request.respond(response);
                } else {
                    let response = Response::from_string("Not Found").with_status_code(404);
                    let _ = request.respond(response);
                }
            }
        });
    }
}
