#include "tau_gate.h"
#include <assert.h>
int main(void) {
    const char *names[] = {"root", "leaf"};
    const char *bad[] = {"root", NULL};
    int edges[] = {0, 1};
    assert(tau_gate_analyze(NULL, 1, names, 2) == NULL);
    assert(tau_gate_analyze(edges, 1, bad, 2) == NULL);
    assert(tau_gate_analyze(edges, 1, names, 1) == NULL);
    for (int i=0; i<100; ++i) {
        FFIPartitionResult *r=tau_gate_analyze(edges,1,names,2);
        assert(r && r->nodes_count==1 && r->converged && r->residual<1e-9);
        assert(r->connectivity_score>1.999 && r->connectivity_score<2.001);
        tau_gate_free_result(r);
        r=tau_gate_analyze(NULL,0,names,1);
        assert(r && r->nodes_count==1 && r->connectivity_score==0);
        tau_gate_free_result(r);
    }
    tau_gate_free_result(NULL);
    return 0;
}
