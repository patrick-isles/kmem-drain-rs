# Kmem-Drain-RS (`kmem-drain-rs`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 2021 Edition](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](https://www.rust-lang.org/)
[![Subsystem: Linux Memory Management](https://img.shields.io/badge/Subsystem-SLAB%20%2F%20IPC%20SHM-red.svg)](https://docs.kernel.org/)
[![Telemetry: Prometheus](https://img.shields.io/badge/Metrics-Prometheus%20:9109-orange.svg)](http://localhost:9109/metrics)

> **Forensic Linux Kernel Memory Sentinel, Zombie Shared-Memory (`shm`) Reaper, Slab Cache Bloat Diagnostic Core & Prometheus Exporter in pure Rust.**

`kmem-drain-rs` hunts down silent, invisible memory leaks that standard user-space tools (`top`, `htop`, `ps`) cannot detect: **orphaned System V & POSIX shared memory segments left behind by dead processes (`SIGKILL`), kernel slab cache bloat (`SUnreclaim`), and direct memory compaction stalls**. It features surgical zero-downtime remediation via `shmctl(IPC_RMID)` and real-time observability on **Prometheus port `:9109`**.

---

## The "Invisible Leak" Problem

In high-throughput enterprise environments (Postgres clusters, deep-learning workers, multiprocessing engines), servers frequently exhaust RAM while all visible processes appear to consume negligible memory:

1. **Zombie Shared Memory (`shmget` / `/dev/shm`)**: When a process that allocated shared memory is terminated abruptly via `SIGKILL` (`kill -9`) or an unhandled panic, its userspace cleanup handlers never run. The Linux kernel retains the allocated RAM segments indefinitely until reboot.
2. **Unreclaimable Kernel Slab Bloat (`SUnreclaim`)**: Leaked dentries, inode caches, and internal buffer structures trap gigabytes of memory inside the kernel space, triggering severe memory compaction stalls and p99 latency spikes.

---

## Architectural Topology

```
           ┌─────────────────────────────────────────────────────────┐
           │        LINUX VIRTUAL FILESYSTEMS & IPC TABLES           │
           │   • /proc/sysvipc/shm (System V Shared Memory Table)    │
           │   • /dev/shm (POSIX Shared Memory Tmpfs)                │
           │   • /proc/meminfo & /proc/slabinfo (Slab Allocators)    │
           │   • /proc/vmstat (Direct Memory Compaction Stalls)      │
           └──────────────────────────┬──────────────────────────────┘
                                      │
           ┌──────────────────────────┴──────────────────────────┐
           │                                                     │
           ▼                                                     ▼
┌─────────────────────────────────────┐ ┌─────────────────────────────────────┐
│       IPC SHM REAPER ENGINE         │ │     KERNEL SLAB & VM SCANNER        │
│  • Parses key, shmid, perms, nattch │ │  • Audits `SUnreclaim` vs. `SReclaim`│
│  • Verifies creator PID in `/proc`  │ │  • Profiles dentries, inodes, kmalloc│
│  • Flags dead-PID unattached zombies│ │  • Catches direct compaction stalls │
└──────────────────┬──────────────────┘ └──────────────────┬──────────────────┘
                   │                                       │
                   └──────────────────┬────────────────────┘
                                      │
                                      ▼ (Atomic Arc<RwLock<KmemSnapshot>>)
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SURGICAL FORENSIC & PURGE CORE                           │
│                                                                             │
│  • Passive Mode: Audits and maps leaked bytes without touching memory.      │
│  • Active Purge (`--purge`): Executes raw `shmctl(shmid, IPC_RMID)`        │
│    syscalls to vaporize orphaned memory segments without server reboot.     │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
             ┌────────────────────────┴────────────────────────┐
             ▼                                                 ▼
┌─────────────────────────────────────┐ ┌─────────────────────────────────────┐
│  PROMETHEUS HTTP EXPORTER (:9109)   │ │    REAL-TIME TERMINAL FORENSICS     │
│  • `kmem_zombie_shm_bytes_total`    │ │  • ASCII memory topology charts     │
│  • `kmem_zombie_shm_segments_count` │ │  • Top leaking slab cache tables    │
│  • `kmem_slab_unreclaimable_bytes`  │ │  • Dead-PID tracking diagnostics    │
│  • `kmem_direct_compaction_stalls`  │ │  • Zero-downtime execution          │
└─────────────────────────────────────┘ └─────────────────────────────────────┘
```

---

## Live Terminal Dashboard Preview

```text
========================================================================
 LINUX KERNEL MEMORY & ZOMBIE IPC SENTINEL [SCANNING] | Mode: PASSIVE FORENSICS
========================================================================
 Total System RAM:     14690.8 MB | Available: 5157.7 MB
 Total Slab Cache:     851.7 MB | Unreclaimable (SUnreclaim): 448.1 MB
 Dirty / Writeback:    51.2 MB / 0.0 MB
 Compaction Stalls:    273 | Kernel OOM Kills: 0
---------------------- Top Active Kernel Slab Caches -------------------
  SLAB NAME        OBJECTS      OBJ SIZE     TOTAL MEM   
  dentry           245120       192 B        44.88 MB
  inode_cache      82400        608 B        47.78 MB
  kmalloc-512      32100        512 B        15.67 MB
---------------------- System V & POSIX Shared Memory ------------------
 Zombie IPC Segments:  1 segments (256.00 MB leaked RAM)
 POSIX /dev/shm Files: 0 files (0.00 MB)
[!] DETECTED UNATTACHED DEAD-PROCESS IPC SEGMENTS:
  • SHMID: 1048576  | Size: 256.00 MB | Creator PID: 99999 [DEAD] | Attached: 0
========================================================================
 Prometheus Exporter: http://0.0.0.0:9109/metrics | Press Ctrl+C to stop
```

---

## Quickstart

### Build & Run
```bash
# Clone the repository
git clone https://github.com/patrick-isles/kmem-drain-rs.git
cd kmem-drain-rs

# Compile optimized release binary
cargo build --release

# Run in passive forensic audit mode
./target/release/kmem-drain-rs

# Run in active purge mode to surgically release dead-PID shared memory
sudo ./target/release/kmem-drain-rs --purge
```

---

## Prometheus Metrics Reference

| Metric Identifier | Metric Type | Description |
|---|---|---|
| `kmem_zombie_shm_bytes_total` | Gauge | Total leaked shared memory trapped in orphaned unattached segments. |
| `kmem_zombie_shm_segments_count` | Gauge | Number of dead-PID unattached shared memory segments. |
| `kmem_slab_unreclaimable_bytes` | Gauge | Kernel memory trapped in unreclaimable slab caches (`SUnreclaim`). |
| `kmem_slab_reclaimable_bytes` | Gauge | Kernel memory in reclaimable slab caches (dentries, inode caches). |
| `kmem_direct_compaction_stalls_total`| Counter | Memory allocation stalls caused by direct compaction contention. |
| `kmem_posix_shm_bytes_total` | Gauge | Total bytes occupied in `/dev/shm` tmpfs. |

---

## Author & License

- **Author**: Patrick Isles `<patrick.isles@pcc.edu>`
- **Repository**: [https://github.com/patrick-isles/kmem-drain-rs](https://github.com/patrick-isles/kmem-drain-rs)
- **License**: MIT
