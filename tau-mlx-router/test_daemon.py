import mlx.core as mx
from cortex_hook import CortexHook
from sparse_cache import KVCacheManager
import numpy as np

def test_daemon():
    print("Initializing τ-Spectral Pruner (TSP)...")
    hook = CortexHook(daemon_path="../target/release/tau-gate", eval_interval=1)
    manager = KVCacheManager(hook)

    # Simulate a context of 30 tokens
    seq_len = 30
    
    # Initialize a dummy KV cache (batch=1, num_heads=4, seq_len=30, head_dim=64)
    k_cache = mx.ones((1, 4, seq_len, 64))
    v_cache = mx.ones((1, 4, seq_len, 64))
    kv_caches = [(k_cache, v_cache)]

    # Initialize position tracker to 30
    manager.position_tracker.step(seq_len)

    print("\n--- TEST 1: GARBAGE_COLLECT ---")
    # Build an attention matrix (batch=1, heads=4, seq_len=30, seq_len=30)
    attn = np.zeros((1, 4, seq_len, seq_len))
    
    # Mainland connections (dense)
    attn[0, :, 0:20, 0:20] = 0.5
            
    # Island connections (dense internally)
    attn[0, :, 20:30, 20:30] = 0.5
            
    # Bridge between mainland and island
    attn[0, :, 20, 19] = 0.5
    attn[0, :, 19, 20] = 0.5

    # Island connects weakly to system sinks, below threat ratio
    attn[0, :, 20, 0] = 0.5

    attention_matrix = mx.array(attn)

    try:
        pruned_caches = manager.update(attention_matrix, kv_caches, sinks=[0, 1, 2, 3])
        print(f"Original KV Sequence Length: {seq_len}")
        print(f"Pruned KV Sequence Length:   {pruned_caches[0][0].shape[2]}")
        print(f"Remaining Position IDs:      {manager.position_tracker.position_ids}")
        
        if pruned_caches[0][0].shape[2] < seq_len:
            print("✅ SUCCESS: Island was successfully garbage collected from the MLX Cache.")
        else:
            print("❌ FAILURE: Island was not pruned.")
    except RuntimeError as e:
        print(f"❌ FAILURE: Unexpected intercept: {e}")

    print("\n--- TEST 2: FATAL_BLOCK ---")
    # Reset attn
    attn = np.zeros((1, 4, seq_len, seq_len))
    # Mainland
    attn[0, :, 0:20, 0:20] = 0.5
    # Small island: just nodes 20 and 21
    attn[0, :, 20:22, 20:22] = 0.5
    # Bridge
    attn[0, :, 20, 19] = 0.5
    attn[0, :, 19, 20] = 0.5
    # Massive connection to system sinks
    # Nodes 20 and 21 connect to all nodes 0-15
    attn[0, :, 20:22, 0:15] = 0.5
    
    attention_matrix_fatal = mx.array(attn)
    try:
        # We need to recreate the manager since it was mutated
        manager2 = KVCacheManager(hook)
        manager2.position_tracker.step(seq_len)
        pruned_caches = manager2.update(attention_matrix_fatal, kv_caches, sinks=[0, 1, 2, 3])
        print("❌ FAILURE: Island was not intercepted!")
    except RuntimeError as e:
        print(f"✅ SUCCESS: Threat intercepted properly! Exception: {e}")

if __name__ == '__main__':
    test_daemon()
