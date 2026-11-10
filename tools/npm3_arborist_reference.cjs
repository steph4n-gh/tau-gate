// Offline virtual-tree reference using the pinned npm installation's own reader.
const fs = require('node:fs');
const path = require('node:path');
const Arborist = require(path.resolve(process.argv[2], 'node_modules/@npmcli/arborist'));
(async () => {
  const tree = await new Arborist({path: process.argv[3], ignoreScripts: true,
    audit: false, offline: true}).loadVirtual();
  const nodes = [], edges = [], unresolved = [];
  for (const node of tree.inventory.values()) {
    nodes.push({path: node.location, name: node.package.name || node.name,
      version: node.package.version || null, link: node.isLink});
    if (node.isLink) continue;
    for (const edge of node.edgesOut.values()) {
      const value = {from: node.location, name: edge.name, type: edge.type};
      if (edge.to) edges.push({...value, to: edge.to.location});
      else unresolved.push(value);
    }
  }
  console.log(JSON.stringify({nodes, edges, unresolved}));
})().catch(error => {
  console.error(error.stack); process.exitCode = 1;
});
