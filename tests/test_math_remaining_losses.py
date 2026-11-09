"""Controls for the external study's exhaustive single-edge-cut argument."""
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
AVAILABLE = all(importlib.util.find_spec(name) for name in ['numpy', 'scipy', 'yaml'])
if AVAILABLE:
    from math_remaining_losses import bridge_cuts, adjacency
    from math_corpus import partition_metrics


@unittest.skipUnless(AVAILABLE, 'requires the optional external math-reference dependencies')
class BridgeOracle(unittest.TestCase):
    def test_bridges_match_all_one_edge_partitions_in_connected_multigraphs(self):
        # Every connected four-node simple graph, with a duplicate and a loop
        # added separately, checks that edge multiplicity cannot invent bridges.
        edges = [(i, j) for i in range(4) for j in range(i)]
        checked = 0
        for mask in range(1 << len(edges)):
            selected = [e for i, e in enumerate(edges) if mask & (1 << i)]
            for additions in [[], [(0, 0)], selected[:1]]:
                graph = {'nodes': list(range(4)), 'edges': selected + additions}
                adj = adjacency(graph)
                reached = {0}
                for _ in range(4):
                    reached.update(v for u in list(reached) for v in adj[u])
                if len(reached) != 4:
                    continue
                expected = {}
                canonical = lambda side: min(tuple(sorted(side)), tuple(sorted(set(range(4)) - set(side))))
                for subset in range(1, (1 << 4) - 1):
                    side = {i for i in range(4) if subset & (1 << i)}
                    metrics = partition_metrics(side, adj)
                    if metrics['cut_edges'] == 1:
                        expected[canonical(side)] = (metrics['ratio_cut'], metrics['conductance'])
                observed = {}
                for cut in bridge_cuts(graph):
                    side = cut['indices']
                    observed[canonical(side)] = (float(cut['ratio_fraction']), float(cut['conductance_fraction']))
                self.assertEqual(expected.keys(), observed.keys())
                for key in expected:
                    for a, b in zip(expected[key], observed[key]):
                        self.assertAlmostEqual(a, b)
                checked += 1
        self.assertGreater(checked, 100)


if __name__ == '__main__':
    unittest.main()
