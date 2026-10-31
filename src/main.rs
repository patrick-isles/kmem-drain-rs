//! Main Entrypoint & Real-Time Terminal Memory Forensics Dashboard
//!
//! Hunts zombie IPC shared memory, monitors slab leaks, and exposes Prometheus metrics on :9109.

mod exporter;
mod shm_reaper;
mod slab_scanner;

use exporter::{KmemExporter, KmemSnapshot};
use shm_reaper::ShmReaper;
use slab_scanner::SlabScanner;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() {
    let args: Vec<String> = env::args().collect();
    let purge_mode = args.contains(&"--purge".to_string());

    println!("\x1b[2J\x1b[H"); // Clear screen
    println!("\x1b[1;35m========================================================================\x1b[0m");
    println!("\x1b[1;37m        KMEM-DRAIN-RS: Linux Kernel Slab & IPC Memory Sentinel         \x1b[0m");
    println!("\x1b[1;35m========================================================================\x1b[0m");

    let initial_mem = SlabScanner::read_memory_health();
    let initial_shm = ShmReaper::scan_sysv_shm();
    let (initial_posix_files, initial_posix_bytes) = ShmReaper::scan_posix_dev_shm();

    let state = Arc::new(RwLock::new(KmemSnapshot {
        kernel_mem: initial_mem,
        shm_segments: initial_shm,
        posix_shm_files: initial_posix_files,
        posix_shm_bytes: initial_posix_bytes,
    }));

    // Start Prometheus Exporter on Port 9109
    let port = 9109;
    KmemExporter::start_exporter(Arc::clone(&state), port);
    println!("\x1b[32m[+] Prometheus Metrics Exporter listening on http://0.0.0.0:{}/metrics\x1b[0m", port);

    // Trap SIGINT / SIGTERM for clean shutdown
    ctrlc::set_handler(move || {
        RUNNING.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    while RUNNING.load(Ordering::SeqCst) {
        let mem = SlabScanner::read_memory_health();
        let mut shm = ShmReaper::scan_sysv_shm();
        let (posix_files, posix_bytes) = ShmReaper::scan_posix_dev_shm();

        // If in purge mode, vaporize zombie segments
        if purge_mode {
            for seg in &mut shm {
                if seg.is_zombie_orphan {
                    let _ = ShmReaper::purge_sysv_segment(seg.shmid);
                }
            }
        }

        // Update atomic state
        {
            let mut writer = state.write().unwrap();
            writer.kernel_mem = mem.clone();
            writer.shm_segments = shm.clone();
            writer.posix_shm_files = posix_files;
            writer.posix_shm_bytes = posix_bytes;
        }

        // Render Forensic TUI Dashboard
        render_dashboard(&mem, &shm, posix_files, posix_bytes, purge_mode);

        thread::sleep(Duration::from_millis(1000));
    }

    println!("\n\x1b[1;33m[!] Shutdown signal caught. Halting kmem-drain-rs gracefully.\x1b[0m");
}

fn render_dashboard(
    mem: &slab_scanner::KernelMemoryState,
    shm: &[shm_reaper::ShmSegment],
    posix_files: usize,
    posix_bytes: u64,
    purge_mode: bool,
) {
    print!("\x1b[H"); // Cursor to top-left
    println!("\x1b[1;35m========================================================================\x1b[0m");
    println!(
        "\x1b[1;37m LINUX KERNEL MEMORY & ZOMBIE IPC SENTINEL \x1b[32m[SCANNING]\x1b[0m | Mode: \x1b[1;{}m{}\x1b[0m",
        if purge_mode { "31" } else { "36" },
        if purge_mode { "ACTIVE PURGE (--purge)" } else { "PASSIVE FORENSICS" }
    );
    println!("\x1b[1;35m========================================================================\x1b[0m");

    let mem_total_mb = mem.mem_total_kb as f64 / 1024.0;
    let mem_avail_mb = mem.mem_available_kb as f64 / 1024.0;
    let slab_total_mb = mem.slab_total_kb as f64 / 1024.0;
    let slab_unreclaim_mb = mem.slab_unreclaimable_kb as f64 / 1024.0;

    println!(" Total System RAM:     {:.1} MB | Available: {:.1} MB", mem_total_mb, mem_avail_mb);
    println!(" Total Slab Cache:     {:.1} MB | Unreclaimable (SUnreclaim): \x1b[1;{}m{:.1} MB\x1b[0m",
        slab_total_mb,
        if slab_unreclaim_mb > 500.0 { "31" } else { "32" },
        slab_unreclaim_mb
    );
    println!(" Dirty / Writeback:    {:.1} MB / {:.1} MB", mem.dirty_kb as f64 / 1024.0, mem.writeback_kb as f64 / 1024.0);
    println!(" Compaction Stalls:    \x1b[1;{}m{}\x1b[0m | Kernel OOM Kills: \x1b[1;{}m{}\x1b[0m",
        if mem.direct_compaction_stalls > 100 { "33" } else { "32" },
        mem.direct_compaction_stalls,
        if mem.oom_kill_events > 0 { "31" } else { "32" },
        mem.oom_kill_events
    );

    println!("\x1b[1;34m---------------------- Top Active Kernel Slab Caches -------------------\x1b[0m");
    println!("  {:<16} {:<12} {:<12} {:<12}", "SLAB NAME", "OBJECTS", "OBJ SIZE", "TOTAL MEM");
    for s in &mem.top_slabs {
        println!("  \x1b[1m{:<16}\x1b[0m {:<12} {:<12} {:.2} MB", s.name, s.active_objs, format!("{} B", s.obj_size_bytes), s.total_size_mb);
    }

    println!("\x1b[1;34m---------------------- System V & POSIX Shared Memory ------------------\x1b[0m");
    let zombie_count = shm.iter().filter(|s| s.is_zombie_orphan).count();
    let zombie_bytes: u64 = shm.iter().filter(|s| s.is_zombie_orphan).map(|s| s.size_bytes).sum();

    println!(
        " Zombie IPC Segments:  \x1b[1;{}m{} segments\x1b[0m ({:.2} MB leaked RAM)",
        if zombie_count > 0 { "31" } else { "32" },
        zombie_count,
        zombie_bytes as f64 / (1024.0 * 1024.0)
    );
    println!(" POSIX /dev/shm Files: {} files ({:.2} MB)", posix_files, posix_bytes as f64 / (1024.0 * 1024.0));

    if zombie_count > 0 {
        println!("\x1b[1;31m[!] DETECTED UNATTACHED DEAD-PROCESS IPC SEGMENTS:\x1b[0m");
        for s in shm.iter().filter(|s| s.is_zombie_orphan).take(3) {
            println!(
                "  • SHMID: {:<8} | Size: {:.2} MB | Creator PID: {} \x1b[31m[DEAD]\x1b[0m | Attached: {}",
                s.shmid,
                s.size_bytes as f64 / (1024.0 * 1024.0),
                s.cpid,
                s.nattch
            );
        }
    } else {
        println!("  \x1b[32m✔ No zombie unattached shared memory segments detected.\x1b[0m");
    }

    println!("\x1b[1;35m========================================================================\x1b[0m");
    println!(" Prometheus Exporter: http://0.0.0.0:9109/metrics | Press Ctrl+C to stop");
}
