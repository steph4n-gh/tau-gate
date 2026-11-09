// Independent package-manager readers, used only by the external corpus experiment.
const fs = require('node:fs');
const path = require('node:path');
const [sourcesFile, modulesPath, output] = process.argv.slice(2);
const classic = require(path.resolve(modulesPath, '@yarnpkg/lockfile'));
const berry = require(path.resolve(modulesPath, '@yarnpkg/parsers'));
const result = {};
for (const item of JSON.parse(fs.readFileSync(sourcesFile, 'utf8'))) {
  if (!item.lockfile.endsWith('yarn.lock')) continue;
  const text = fs.readFileSync(item.lock, 'utf8');
  if (text.includes('# yarn lockfile v1')) {
    const parsed = classic.parse(text);
    if (parsed.type !== 'success') throw new Error(`${item.repository}: ${parsed.type}`);
    result[item.id] = {format: 'classic', records: parsed.object};
  } else {
    result[item.id] = {format: 'berry', records: berry.parseSyml(text)};
  }
}
fs.writeFileSync(output, JSON.stringify(result));
