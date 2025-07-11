//! Collects TCP packet latency stats using BPF and traces:
//! * `tcp_destroy_sock`
//! * `tcp_probe`
//! * `tcp_rcv_space_adjust`
//!
//! And produces these stats:
//! * `tcp/receive/packet_latency`

const NAME: &str = "tcp_packet_latency";

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/tcp_packet_latency.bpf.rs"));
}

mod stats;

use bpf::*;
use stats::*;

use crate::agent::*;

use std::sync::Arc;

#[distributed_slice(SAMPLERS)]
fn init(config: Arc<Config>) -> SamplerResult {
    if !config.enabled(NAME) {
        return Ok(None);
    }

    let bpf = BpfBuilder::new(
        NAME,
        BpfProgStats {
            run_time: &BPF_RUN_TIME,
            run_count: &BPF_RUN_COUNT,
        },
        ModSkelBuilder::default,
    )
    .histogram("latency", &TCP_PACKET_LATENCY)
    .build()?;

    Ok(Some(Box::new(bpf)))
}

impl SkelExt for ModSkel<'_> {
    fn map(&self, name: &str) -> &libbpf_rs::Map {
        match name {
            "latency" => &self.maps.latency,
            _ => unimplemented!(),
        }
    }
}

impl OpenSkelExt for ModSkel<'_> {
    fn log_prog_instructions(&self) {
        debug!(
            "{NAME} tcp_probe() BPF instruction count: {}",
            self.progs.tcp_probe.insn_cnt()
        );
        debug!(
            "{NAME} tcp_rcv_space_adjust() BPF instruction count: {}",
            self.progs.tcp_rcv_space_adjust.insn_cnt()
        );
        debug!(
            "{NAME} tcp_destroy_sock() BPF instruction count: {}",
            self.progs.tcp_destroy_sock.insn_cnt()
        );
    }
}
