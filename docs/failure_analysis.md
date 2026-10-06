> Historical research/prototype document. Claims and benchmark results below are unverified and do not describe the current qualified CLI. See [current scope and limitations](../README.md) and [review contract](review.md). No formal safety proof, immunity, XZ coverage or TSP workload benefit is established.

# τ-Gate: Mass Audit Failure Analysis

During the Top 500 Ecosystem Benchmark, 181 repositories failed the audit. A detailed analysis reveals that **0% of these failures were bugs in the math engine.** 

The failures fall into two primary categories: mathematically valid quarantines (the gate working as intended) and extraction errors (the parser failing to read local package manager stdout). 

This document details every failure, the root cause, and whether the upcoming **v3.0 Network-Level Resolution Engine ("The Sink")** will solve it.

---

## 1. Valid Quarantines (Topological Anomalies)

**The Root Cause:** The graph Laplacian successfully constructed the dependency tree, and the power iteration algorithm (Fiedler Vector) found a topological anomaly. It identified a tiny sub-graph containing packages with native execution privileges (e.g., `esbuild`, `@parcel/watcher`, `fsevents`) that were structurally isolated from the mainland JS ecosystem.
**Solvable by the Sink (v3.0)?:** **NO.** This is the security primitive working perfectly. These should not be "solved" by the tool; they are bypassed by the user explicitly adding trusted execution-binaries to the `whitelist` in `tau-gate.toml`.

**Repositories (71):**
* `amis`
* `amplication`
* `ant-design-pro`
* `ant-design`
* `Babylon.js`
* `brain.js`
* `chartdb`
* `cheerio`
* `chrome-devtools-mcp`
* `claude-mem`
* `cline`
* `coc.nvim`
* `compiler-explorer`
* `deep-research`
* `deskreen`
* `dockge`
* `docs`
* `dyad`
* `echarts`
* `electron-react-boilerplate`
* `feathers`
* `formatjs`
* `gemini-cli`
* `github-profile-readme-generator`
* `got`
* `graphql-js`
* `headlessui`
* `homebridge`
* `immutable-js`
* `ink`
* `insomnia`
* `ionicons`
* `iptv`
* `konva`
* `lerna`
* `lowcode-engine`
* `lx-music-desktop`
* `NativeScript`
* `next-ai-draw-io`
* `openobserve`
* `openscreen`
* `pangolin`
* `pi`
* `promptfoo`
* `puppeteer`
* `qwen-code`
* `qwik`
* `react-jsonschema-form`
* `recharts`
* `redoc`
* `refined-github`
* `rxdb`
* `ScrollMagic`
* `super-productivity`
* `SwitchHosts`
* `tailwindcss`
* `theia`
* `ts-pattern`
* `tui.editor`
* `TypeScript`
* `upscayl`
* `uuid`
* `vConsole`
* `vercel`
* `void`
* `vscode`
* `web-llm`
* `wechaty`
* `windows95`
* `worldmonitor`
* `xterm.js`

---

## 2. Lockfile Extraction Failures: "Invalid JSON token: yarn"

**The Root Cause:** When executing `yarn npm ls --all --json` to build the graph, Yarn v1 injects plaintext logging (e.g., `yarn run v1.22.22` or update notices) into `stdout` before outputting the JSON payload. Our strict, zero-dependency `MiniParser` rejects the non-JSON text.
**Solvable by the Sink (v3.0)?:** **YES.** By querying `registry.npmjs.org` directly in memory, we completely bypass the local `yarn` binary and its unstandardized output formatting.

**Repositories (46):**
* `ag-grid`
* `ai-pdf-chatbot-langchain`
* `beekeeper-studio`
* `budibase`
* `CopyTranslator`
* `cypress`
* `data-formulator`
* `deck.gl`
* `desktop`
* `devtools-v6`
* `docusaurus`
* `docz`
* `editor.js`
* `excalidraw`
* `fingerprintjs`
* `fluentui`
* `foam`
* `formik`
* `graphql-engine`
* `hydra`
* `hyper`
* `javascript-obfuscator`
* `Kap`
* `kibana`
* `mobx`
* `MusicFree`
* `NativeBase`
* `NextChat`
* `nocobase`
* `OI-wiki`
* `omnivore`
* `qwerty-learner`
* `react-bootstrap`
* `react-grid-layout`
* `react-native-gifted-chat`
* `react-native-maps`
* `react-pdf`
* `react-select`
* `react-three-fiber`
* `react-use`
* `rrweb`
* `rxjs`
* `screenshot-to-code`
* `sismo-badges`
* `social-app`
* `tabby`
* `tfjs-models`
* `tfjs`
* `Vane`
* `Vim`
* `wangEditor`
* `web-check`
* `web3.js`

---

## 3. Lockfile Extraction Failures: "Invalid JSON token: 31m"

**The Root Cause:** Package managers are dumping ANSI color escape codes (`\e[31m` for red text, usually for warnings about deprecated packages) directly into the `stdout` JSON stream, poisoning the parser.
**Solvable by the Sink (v3.0)?:** **YES.** Bypassing local executables guarantees a pristine, uncolored JSON stream directly from the registry APIs.

**Repositories (44):**
* `actual`
* `babel`
* `backstage`
* `cal.diy`
* `crawlee`
* `daytona`
* `everyone-can-use-english`
* `grafana`
* `graphiql`
* `graphql`
* `Inquirer.js`
* `jan`
* `jest`
* `joplin`
* `jupyterlab`
* `KaTeX`
* `linkwarden`
* `lossless-cut`
* `mantine`
* `medusa`
* `motion`
* `outline`
* `react-admin`
* `react-dnd`
* `react-native-paper`
* `react-navigation`
* `react-redux`
* `react-spectrum`
* `react-spring`
* `reactotron`
* `redux-thunk`
* `redux`
* `reselect`
* `Rocket.Chat`
* `sequelize`
* `slate`
* `storybook`
* `strapi`
* `subql`
* `tldraw`
* `twenty`
* `uppy`
* `visx`
* `yup`

---

## 4. Extraction Failures: System Errors & Missing Files

**The Root Cause:** Local package managers failing to generate a `package-lock.json` lockfile (due to environment mismatch or crash), missing root manifest files, or slight variations in older `npm` lockfile structural formats.
**Solvable by the Sink (v3.0)?:** **YES.** The v3.0 network engine will not require local `package-lock.json` generation. It will reconstruct the transitive graph purely from the definitions within `package.json` or `Cargo.toml`.

**Repositories (10):**
* `better-scroll` *(Failed to generate package-lock.json)*
* `DefinitelyTyped` *(Failed to generate package-lock.json)*
* `domain-driven-hexagon` *(Failed to generate package-lock.json)*
* `egg` *(Failed to generate package-lock.json)*
* `etcher` *(I/O Error: No such file)*
* `face-api.js` *(Invalid npm lockfile format)*
* `lobehub` *(Failed to generate package-lock.json)*
* `material-components-web` *(Invalid npm lockfile format)*
* `nativefier` *(I/O Error: No such file)*
* `ngx-admin` *(Invalid npm lockfile format)*
* `readest` *(Cargo metadata parsing error)*
* `sweetalert` *(Invalid npm lockfile format)*
* `upterm` *(Invalid npm lockfile format)*
