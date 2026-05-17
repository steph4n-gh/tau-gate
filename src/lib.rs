pub mod config;
pub mod daemon;
pub mod error;
pub mod graph;
pub mod graph_impl;
pub mod math;
pub mod network;
pub mod parser;
pub mod semver;
pub mod telemetry;

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
}

#[no_mangle]
pub unsafe extern "C" fn tau_gate_analyze(
    edges_ptr: *const c_int,
    edges_count: usize,
    nodes_ptr: *const *const c_char,
    nodes_count: usize,
) -> *mut FFIPartitionResult {
    let mut graph = DiGraph::new();

    // 1. Add nodes
    for i in 0..nodes_count {
        let ptr = unsafe { *nodes_ptr.add(i) };
        if ptr.is_null() {
            continue;
        }
        let c_str = unsafe { CStr::from_ptr(ptr) };
        let name = c_str.to_string_lossy().into_owned();
        graph.add_node(name);
    }

    // 2. Add edges
    let edges_slice = unsafe { std::slice::from_raw_parts(edges_ptr, edges_count * 2) };
    for i in 0..edges_count {
        let u = edges_slice[i * 2] as usize;
        let v = edges_slice[i * 2 + 1] as usize;
        if u < nodes_count && v < nodes_count {
            graph.add_edge(u, v);
        }
    }

    // 3. Analyze
    match analyze_graph(&graph) {
        Ok(res) => {
            let initial_nodes_count = res.partition_b.len();
            let mut c_nodes = Vec::with_capacity(initial_nodes_count);
            for node in res.partition_b {
                if let Ok(c_str) = CString::new(node) {
                    c_nodes.push(c_str.into_raw());
                }
            }

            c_nodes.shrink_to_fit();
            let actual_nodes_count = c_nodes.len();
            let nodes_ptr = c_nodes.as_mut_ptr();
            std::mem::forget(c_nodes);

            let result = Box::new(FFIPartitionResult {
                nodes: nodes_ptr,
                nodes_count: actual_nodes_count,
                tau: res.tau,
                connectivity_score: res.connectivity_score,
            });

            Box::into_raw(result)
        }
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn tau_gate_free_result(ptr: *mut FFIPartitionResult) {
    if !ptr.is_null() {
        {
            let result = Box::from_raw(ptr);
            let nodes = Vec::from_raw_parts(result.nodes, result.nodes_count, result.nodes_count);
            for node in nodes {
                if !node.is_null() {
                    let _ = CString::from_raw(node);
                }
            }
        }
    }
}
