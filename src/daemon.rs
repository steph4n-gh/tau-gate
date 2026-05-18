use crate::error::Result;
use crate::parser::JsonNode;
use crate::parser::MiniParser;
use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};

pub fn run() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        if let Ok(json) = MiniParser::parse_json(&line) {
            let mut edges = Vec::new();
            let mut sinks = BTreeSet::new();
            let threat_threshold = json
                .get("threat_threshold")
                .and_then(get_f64)
                .unwrap_or(2.0);

            if let Some(sinks_arr) = json.get("sinks").and_then(|s| s.as_array()) {
                for s in sinks_arr {
                    if let Some(n) = get_f64(s) {
                        sinks.insert(n as usize);
                    }
                }
            }

            if let Some(edges_arr) = json.get("edges").and_then(|e| e.as_array()) {
                for edge in edges_arr {
                    if let Some(e) = edge.as_array() {
                        if e.len() == 2 {
                            let u = get_f64(&e[0]).unwrap_or(0.0) as usize;
                            let v = get_f64(&e[1]).unwrap_or(0.0) as usize;
                            edges.push((u, v));
                        }
                    }
                }
            }

            let mut max_node = 0;
            for &(u, v) in &edges {
                if u > max_node {
                    max_node = u;
                }
                if v > max_node {
                    max_node = v;
                }
            }
            let n = max_node + 1;

            if n < 3 {
                println!(r#"{{"action":"ALLOW","island_indices":[]}}"#);
                let _ = stdout.flush();
                continue;
            }

            let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
            let mut degrees = vec![0.0; n];

            for &(u, v) in &edges {
                if !sinks.contains(&u) && !sinks.contains(&v) && u != v {
                    adj[u].push(v);
                    adj[v].push(u);
                    degrees[u] += 1.0;
                    degrees[v] += 1.0;
                }
            }

            let max_degree = degrees.iter().copied().fold(0.0, f64::max);
            let mut partition_b = Vec::new();

            if max_degree > 0.0 {
                let alpha = 1.0 / (2.0 * max_degree + 1.1);
                let mut v_vec = vec![0.0; n];
                for i in 0..n {
                    if !sinks.contains(&i) {
                        v_vec[i] = (i as f64).sin();
                    }
                }

                let iterations = 1000;
                let tolerance = 1e-9;
                for _ in 0..iterations {
                    let mut sum = 0.0;
                    let mut count = 0.0;
                    for i in 0..n {
                        if !sinks.contains(&i) {
                            sum += v_vec[i];
                            count += 1.0;
                        }
                    }
                    let mean = if count > 0.0 { sum / count } else { 0.0 };
                    for i in 0..n {
                        if !sinks.contains(&i) {
                            v_vec[i] -= mean;
                        }
                    }

                    let mut v_next = vec![0.0; n];
                    for i in 0..n {
                        if sinks.contains(&i) {
                            continue;
                        }
                        v_next[i] = (1.0 - alpha * degrees[i]) * v_vec[i];
                        for &neighbor in &adj[i] {
                            v_next[i] += alpha * v_vec[neighbor];
                        }
                    }

                    let mut norm_sq = 0.0;
                    for i in 0..n {
                        if !sinks.contains(&i) {
                            norm_sq += v_next[i] * v_next[i];
                        }
                    }
                    let norm = norm_sq.sqrt();
                    if norm < 1e-15 {
                        break;
                    }

                    let mut max_diff = 0.0;
                    for i in 0..n {
                        if !sinks.contains(&i) {
                            v_next[i] /= norm;
                            max_diff = f64::max(max_diff, (v_next[i] - v_vec[i]).abs());
                        }
                    }
                    v_vec = v_next;
                    if max_diff < tolerance {
                        break;
                    }
                }

                let mut indexed_fiedler: Vec<(usize, f64)> = v_vec
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(i, _)| !sinks.contains(i))
                    .collect();
                indexed_fiedler
                    .sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

                let mut max_gap = -1.0;
                let mut cut_idx = 0;
                if indexed_fiedler.len() > 1 {
                    for i in 0..(indexed_fiedler.len() - 1) {
                        let gap = (indexed_fiedler[i + 1].1 - indexed_fiedler[i].1).abs();
                        if gap > max_gap {
                            max_gap = gap;
                            cut_idx = i;
                        }
                    }
                }

                let mut side_large = Vec::new();
                let mut side_small = Vec::new();
                for (i, val) in indexed_fiedler.iter().enumerate() {
                    if i <= cut_idx {
                        side_small.push(val.0);
                    } else {
                        side_large.push(val.0);
                    }
                }

                partition_b = if side_small.len() < side_large.len() {
                    side_small
                } else {
                    side_large
                };
            }

            let system_prompt_len = json
                .get("system_prompt_length")
                .and_then(get_f64)
                .unwrap_or(15.0) as usize;

            // Semantic Threat Calculation (v3.0.2 Mitigation: Attention Sink Offset)
            // We ignore tokens 0-4 as these are mathematically proven "Attention Sinks" (StreamingLLM, 2023).
            let mut to_system = 0.0;
            let mut internal = 0.0;
            let island: BTreeSet<usize> = partition_b.iter().copied().collect();

            for &(u, v) in &edges {
                if island.contains(&u) {
                    if v >= 5 && v <= system_prompt_len {
                        to_system += 1.0;
                    } else if island.contains(&v) {
                        internal += 1.0;
                    }
                }
                if island.contains(&v) && u != v {
                    if u >= 5 && u <= system_prompt_len {
                        to_system += 1.0;
                    } else if island.contains(&u) {
                        internal += 1.0;
                    }
                }
            }

            // v3.0.5 Ironclad: Explicitly handle infinity for perfect jailbreaks (to_system == 0).
            let injection_ratio = if to_system > 0.0 {
                internal / to_system
            } else if internal > 0.0 {
                f64::INFINITY
            } else {
                0.0
            };

            let action = if !island.is_empty() && injection_ratio > threat_threshold {
                "FATAL_BLOCK"
            } else if !island.is_empty() {
                "GARBAGE_COLLECT"
            } else {
                "ALLOW"
            };

            let island_json = partition_b
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let res = format!(
                r#"{{"action":"{}","island_indices":[{}]}}"#,
                action, island_json
            );
            println!("{}", res);
            let _ = stdout.flush();
        }
    }
    Ok(())
}

fn get_f64(n: &JsonNode) -> Option<f64> {
    match n {
        JsonNode::Number(num) => Some(*num),
        _ => None,
    }
}
