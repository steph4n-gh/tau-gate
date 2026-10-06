pub mod config;
pub mod daemon;
pub mod digest;
pub mod error;
pub mod graph;
pub mod graph_impl;
pub mod math;
pub mod network;
pub mod parser;
pub mod pnpm;
pub mod review;
pub mod semver;
pub mod telemetry;
pub mod yarn;

use graph_impl::DiGraph;
use math::analyze_graph;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_double, c_int};
use std::ptr;

#[repr(C)]
pub struct FFIPartitionResult {
    pub nodes: *mut *mut c_char,
    pub nodes_count: usize,
    pub tau: c_double,
    pub connectivity_score: c_double,
    pub converged: c_int,
    pub residual: c_double,
    pub iterations: usize,
}

/// Analyze a caller-owned graph; NULL means invalid input or analysis failure.
/// # Safety
/// See include/tau_gate.h: pointers must reference valid arrays and NUL-terminated names.
#[no_mangle]
pub unsafe extern "C" fn tau_gate_analyze(
    edges_ptr: *const c_int,
    edges_count: usize,
    nodes_ptr: *const *const c_char,
    nodes_count: usize,
) -> *mut FFIPartitionResult {
    if nodes_count == 0
        || nodes_count > 1_000_000
        || edges_count > 10_000_000
        || nodes_ptr.is_null()
        || (edges_count > 0 && edges_ptr.is_null())
    {
        return ptr::null_mut();
    }
    let Some(edge_len) = edges_count.checked_mul(2) else {
        return ptr::null_mut();
    };
    std::panic::catch_unwind(|| {
        let mut graph = DiGraph::new();
        for i in 0..nodes_count {
            let p = *nodes_ptr.add(i);
            if p.is_null() {
                return ptr::null_mut();
            }
            graph.add_node(CStr::from_ptr(p).to_string_lossy().into_owned());
        }
        let edges = if edges_count == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(edges_ptr, edge_len)
        };
        for edge in edges.chunks_exact(2) {
            if edge[0] < 0
                || edge[1] < 0
                || edge[0] as usize >= nodes_count
                || edge[1] as usize >= nodes_count
            {
                return ptr::null_mut();
            }
            graph.add_edge(edge[0] as usize, edge[1] as usize);
        }
        match analyze_graph(&graph) {
            Ok(res) => {
                let nodes: Box<[*mut c_char]> = res
                    .partition_b
                    .into_iter()
                    .filter_map(|n| CString::new(n).ok())
                    .map(CString::into_raw)
                    .collect();
                let count = nodes.len();
                let raw = Box::into_raw(nodes) as *mut *mut c_char;
                Box::into_raw(Box::new(FFIPartitionResult {
                    nodes: raw,
                    nodes_count: count,
                    tau: res.tau,
                    connectivity_score: res.connectivity_score,
                    converged: res.converged as c_int,
                    residual: res.residual,
                    iterations: res.iterations,
                }))
            }
            Err(_) => ptr::null_mut(),
        }
    })
    .unwrap_or(ptr::null_mut())
}

/// Release a result returned by tau_gate_analyze. NULL is accepted.
/// # Safety
/// Non-NULL must be an unmodified, live result from this library, freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn tau_gate_free_result(ptr: *mut FFIPartitionResult) {
    if !ptr.is_null() {
        {
            let result = Box::from_raw(ptr);
            let nodes = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                result.nodes,
                result.nodes_count,
            ));
            for &node in nodes.iter() {
                if !node.is_null() {
                    let _ = CString::from_raw(node);
                }
            }
        }
    }
}

#[cfg(test)]
mod ffi_tests {
    use super::*;
    #[test]
    fn null_bounds_zero_edges_and_ownership() {
        unsafe {
            let name = CString::new("a").unwrap();
            let names = [name.as_ptr(), std::ptr::null()];
            assert!(tau_gate_analyze(ptr::null(), 0, names.as_ptr(), 2).is_null());
            assert!(tau_gate_analyze(ptr::null(), 1, names.as_ptr(), 1).is_null());
            assert!(tau_gate_analyze([0, 1].as_ptr(), 1, names.as_ptr(), 1).is_null());
            assert!(tau_gate_analyze([-1, 0].as_ptr(), 1, names.as_ptr(), 1).is_null());
            assert!(tau_gate_analyze(ptr::null(), 0, ptr::null(), 1).is_null());
            for _ in 0..100 {
                let result = tau_gate_analyze(ptr::null(), 0, names.as_ptr(), 1);
                assert!(!result.is_null());
                assert_eq!((*result).nodes_count, 1);
                assert_eq!((*result).connectivity_score, 0.0);
                tau_gate_free_result(result);
            }
            tau_gate_free_result(ptr::null_mut());
        }
    }
}
