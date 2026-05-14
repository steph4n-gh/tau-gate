import json
import subprocess
import mlx.core as mx
from typing import Dict, Any, List

class CortexHook:
    def __init__(self, daemon_path: str = "../target/release/tau-gate", eval_interval: int = 64, threshold: float = 0.015):
        self.daemon_path = daemon_path
        self.eval_interval = eval_interval
        self.threshold = threshold
        self.token_counter = 0
        self.daemon = subprocess.Popen(
            [self.daemon_path, "daemon"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )

    def evaluate_attention(self, attention_matrix: mx.array, sinks: List[int]) -> Dict[str, Any]:
        """
        Evaluates the attention matrix every eval_interval tokens.
        attention_matrix shape: [batch, heads, seq_len, seq_len]
        """
        self.token_counter += 1
        if self.token_counter % self.eval_interval != 0:
            return {"action": "ALLOW", "island_indices": []}

        # Constraint 2: Collapse heads (mean across axis 1)
        a_2d = mx.mean(attention_matrix, axis=1)
        
        # Looking at batch 0
        a_2d = a_2d[0]

        # Symmetrize to make undirected graph: A_sym = max(A, A.T)
        a_sym = mx.maximum(a_2d, a_2d.T)

        # Thresholding
        thresholded = a_sym > self.threshold

        # CRITICAL: mx.eval() before converting to list
        mx.eval(thresholded)

        import numpy as np
        # Build edge list using numpy since MLX doesn't have argwhere
        indices = np.argwhere(np.array(thresholded)).tolist()
        edges = []
        for pair in indices:
            u, v = pair[0], pair[1]
            if u != v:
                edges.append([u, v])

        payload = {
            "edges": edges,
            "sinks": sinks
        }

        # Send to daemon over NDJSON
        self.daemon.stdin.write(json.dumps(payload) + "\n")
        self.daemon.stdin.flush()

        # Read response
        response_line = self.daemon.stdout.readline()
        if not response_line:
            raise RuntimeError("CortexHook: Daemon connection lost.")

        return json.loads(response_line)

    def __del__(self):
        if hasattr(self, 'daemon') and self.daemon.poll() is None:
            self.daemon.terminate()
