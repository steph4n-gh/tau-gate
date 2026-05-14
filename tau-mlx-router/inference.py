import mlx.core as mx
import mlx.nn as nn
from typing import Generator, List, Any
import types

from cortex_hook import CortexHook
from sparse_cache import KVCacheManager, SparsePositionTracker

def patch_attention_for_extraction(model: nn.Module):
    """
    Monkey-patches the final transformer layer's attention block to intercept and store
    the raw attention matrix during the forward pass.
    Most MLX models discard this to save VRAM. We need it for the Fiedler vector.
    """
    # Assuming a LLaMA-like architecture where layers are in `model.model.layers`
    if not hasattr(model, 'model') or not hasattr(model.model, 'layers'):
        print("Warning: Unrecognized model architecture. Cannot patch attention.")
        return

    last_layer = model.model.layers[-1]
    attention = last_layer.self_attn

    # Save the original forward method
    original_call = attention.__call__

    def extracted_call(self, x, mask=None, cache=None):
        # We need to intercept the QK^T matrix before the softmax/V multiplication.
        # Since we can't easily rip apart the inner MLX fast.scaled_dot_product_attention,
        # we manually compute the attention matrix for the router.
        
        # 1. Project Q, K, V
        queries, keys, values = self.q_proj(x), self.k_proj(x), self.v_proj(x)
        
        # Reshape for heads
        B, L, _ = queries.shape
        queries = queries.reshape(B, L, self.n_heads, -1).transpose(0, 2, 1, 3)
        keys = keys.reshape(B, L, self.n_kv_heads, -1).transpose(0, 2, 1, 3)
        values = values.reshape(B, L, self.n_kv_heads, -1).transpose(0, 2, 1, 3)
        
        # We assume RoPE is applied inside the original call. We will just let the original call 
        # do the heavy lifting for the actual forward pass, but we recompute QK^T here for the router.
        # (In production, you'd rewrite the layer to avoid double computation).
        
        # If there's a cache, K and V need to be concatenated
        if cache is not None:
            # We assume cache is an mlx.nn.KVCache
            k_cache, v_cache = cache.keys, cache.values
            if k_cache is not None:
                full_keys = mx.concatenate([k_cache, keys], axis=2)
            else:
                full_keys = keys
        else:
            full_keys = keys

        # Calculate raw attention weights: Q * K^T / sqrt(d)
        scale = 1.0 / mx.sqrt(queries.shape[-1])
        scores = (queries * scale) @ full_keys.transpose(0, 1, 3, 2)
        
        # Store it globally on the model instance so the inference loop can grab it
        model.last_attention_matrix = scores
        
        # Call the original efficient MLX attention for the actual inference
        return original_call(x, mask=mask, cache=cache)

    # Bind the new method to the attention instance
    attention.__call__ = types.MethodType(extracted_call, attention)


def patch_rope_for_sparse_positions(model: nn.Module, tracker: SparsePositionTracker):
    """
    Monkey-patches the RoPE layers to use our SparsePositionTracker instead of MLX's
    default contiguous `offset + arange` logic. This is the hardest part of the infinite context hack.
    """
    if not hasattr(model, 'model') or not hasattr(model.model, 'layers'):
        return

    for layer in model.model.layers:
        attention = layer.self_attn
        if hasattr(attention, 'rope'):
            rope_layer = attention.rope
            
            def sparse_rope_call(self, x, offset):
                # IGNORE the contiguous `offset` provided by MLX.
                # Retrieve the exact, fragmented position IDs from the tracker.
                seq_len = x.shape[2] # Shape is typically [batch, heads, seq_len, dims]
                
                # Fetch the true historical positions corresponding to this sequence length
                true_positions = tracker.get_positions()[-seq_len:]
                positions = mx.array(true_positions, dtype=x.dtype)
                
                # Manually compute Rotary Position Embeddings
                freqs = mx.exp(-mx.arange(0, self.dims, 2, dtype=mx.float32) * (mx.log(self.base) / self.dims))
                theta = positions[..., None] * freqs[None, ...]
                
                costheta = mx.cos(theta)
                sintheta = mx.sin(theta)
                
                x1 = x[..., ::2]
                x2 = x[..., 1::2]
                rx1 = x1 * costheta - x2 * sintheta
                rx2 = x1 * sintheta + x2 * costheta
                
                # Interleave rx1 and rx2
                rx = mx.concatenate([rx1[..., None], rx2[..., None]], axis=-1)
                rx = rx.reshape(x.shape)
                return rx
                
            rope_layer.__call__ = types.MethodType(sparse_rope_call, rope_layer)


def generate_infinite_context(
    model: nn.Module, 
    prompt: mx.array, 
    max_tokens: int = 1000
) -> Generator[mx.array, None, None]:
    """
    A custom MLX decoding loop that natively integrates the TSP Router.
    """
    print("[TSP] Initializing Neuro-Symbolic Daemon...")
    hook = CortexHook(daemon_path="../supplychain/target/release/tau-gate", eval_interval=64)
    kv_manager = KVCacheManager(hook)

    print("[TSP] Patching MLX RoPE & Attention Layers...")
    patch_rope_for_sparse_positions(model, kv_manager.position_tracker)
    patch_attention_for_extraction(model)

    # Initialize MLX KV Caches
    kv_caches = [nn.KVCache(model.model.layers[0].self_attn.head_dim, model.model.layers[0].self_attn.n_kv_heads) for _ in model.model.layers]
    
    y = prompt
    
    print("[TSP] Beginning Inference Loop...")
    for i in range(max_tokens):
        
        # Step the tracker for the new token(s)
        kv_manager.position_tracker.step(y.shape[1])
        
        # Forward pass
        logits, cache = model(y, cache=kv_caches)
        
        # Sample the next token
        y = mx.argmax(logits[:, -1, :], axis=-1, keepdims=True)
        yield y
        
        # Trigger the TSP router every `eval_interval` tokens
        if hasattr(model, 'last_attention_matrix') and hook.token_counter % hook.eval_interval == 0:
            attn_matrix = model.last_attention_matrix
            
            # Extract raw (K, V) arrays from the MLX objects
            raw_caches = [(c.keys, c.values) for c in kv_caches]
            
            # Route through the Rust daemon
            pruned_raw_caches = kv_manager.update(attn_matrix, raw_caches, sinks=[0, 1, 2, 3])
            
            # Repack the pruned arrays back into the MLX objects
            for cache_obj, (pk, pv) in zip(kv_caches, pruned_raw_caches):
                cache_obj.keys = pk
                cache_obj.values = pv
                # CRITICAL: Update the offset so MLX knows the cache shrank
                cache_obj.offset = pk.shape[2] 

if __name__ == "__main__":
    print("τ-Spectral Pruner (TSP) Inference Module Loaded.")
    print("To use: import `generate_infinite_context` and pass an mlx_lm loaded model.")
