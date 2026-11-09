#ifndef TAU_GATE_H
#define TAU_GATE_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* The first four fields retain the v3 prefix. Rebuild bindings to access appended fields.
 * Results are estimates, not certified eigenpairs or a validated VRAM pruning policy.
 * nodes is the primary ratio-cut partition. tau is a threshold on its selected
 * Ritz projection; the audit JSON exposes projection and conductance alternatives.
 * This C layout is unchanged and does not expose those additional diagnostics. */
typedef struct {
    char **nodes;
    size_t nodes_count;
    double tau;
    double connectivity_score;
    int converged;
    double residual;
    size_t iterations;
} FFIPartitionResult;
/* Edges: edges_count pairs of zero-based int endpoints. nodes_count must be 1..1000000;
 * edges_count <= 10000000. All names must be valid non-NULL NUL-terminated strings.
 * Caller retains inputs; no input may be mutated/freed during the call. An edges pointer
 * may be NULL only when edges_count==0. All non-NULL pointers must address valid arrays.
 * Invalid values or a recoverable Rust panic return NULL; arbitrary dangling pointers
 * cannot be validated. Returned storage is owned by this library. */
FFIPartitionResult *tau_gate_analyze(const int *edges, size_t edges_count,
                                   const char *const *nodes, size_t nodes_count);
/* Free once with this function only; NULL is allowed. Do not mutate result fields. */
void tau_gate_free_result(FFIPartitionResult *result);
#ifdef __cplusplus
}
#endif
#endif
