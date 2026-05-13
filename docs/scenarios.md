# The Gatekeeper's Guide: Why and How the Gate Shuts

$\tau$-Gate doesn't just look for "bad guys"; it looks for **suspicious social structures**. In the real world, supply chain attacks follow predictable topological patterns. This guide explains how the math translates into real-world security.

---

## 🚫 Scenario 1: The "Typosquatter" (The Isolated Island)
**The Setup:** You accidentally install `asttro` instead of `astro`. This fake package is tiny, has zero dependencies, and immediately tries to run a script to steal your `.env` variables.

*   **Mathematical Signal:** **Smallest Partition < 15%**.
*   **The Math Result:** The `max_gap` snaps the graph at the single thread connecting your app to the fake package. The resulting "Island" partition contains only 1 node.
*   **The Verdict:** **CRITICAL ANOMALY.** 
*   **Real World Meaning:** "Why is a package that nobody else in the entire world uses demanding the power to execute code on my machine?"

---

## 🚫 Scenario 2: The "Sleeper Cell" (Transitive Deep Bridge)
**The Setup:** A tiny, deep utility library (like `is-number` or `ansi-regex`) is hijacked 10 levels deep. It has been quiet for years, but a new malicious version adds a `postinstall` script to exfiltrate SSH keys during CI/CD.

*   **Mathematical Signal:** **Extreme Connectivity Isolation ($\lambda_2 < 10^{-4}$)**.
*   **The Math Result:** Even though the library is "buried," it is still a **structural bottleneck**. The Fiedler Vector identifies that the entire project "snaps" at the point where this utility library enters the tree.
*   **The Verdict:** **CRITICAL ANOMALY.**
*   **Real World Meaning:** "This deep sub-dependency is structurally isolated from the rest of the project. It has created a 'private tunnel' to system execution."

---

## 🚫 Scenario 3: The "Trojan Horse" (The Bloated Trojan)
**The Setup:** An attacker knows about spectral analysis. To avoid looking "small," they add 500 popular, safe dependencies (like `lodash`, `react`, `zod`) to their malicious package. They want to look like a "Big, Trusted Continent."

*   **Mathematical Signal:** **Low Connectivity Score + Anomaly Partition**.
*   **The Math Result:** While the partition size might grow to **20% or 30%** (bypassing the size rule), the **Connectivity Score ($\lambda_2$)** remains near zero. The math sees that the 500 nodes are "bolted on" but still only connected to the main project by one tiny, fragile thread.
*   **The Verdict:** **CRITICAL ANOMALY (Hardened Edition).**
*   **Real World Meaning:** "This package is trying to buy trust by bringing a massive crowd with it, but it's still hiding in an alleyway. Access denied."

---

## 🚫 Scenario 4: The "Internal Leak" (Monorepo Workspace Bridge)
**The Setup:** A local package inside your own monorepo has been compromised by a developer's hijacked machine. It starts bridging internal packages to suspicious external registry URLs.

*   **Mathematical Signal:** **Small Partition + execution/remote_source sinks**.
*   **The Math Result:** The tool identifies that an internal bridge has been formed to a non-standard source or an unauthorized execution point.
*   **The Verdict:** **CRITICAL ANOMALY.**
*   **Real World Meaning:** "An internal component is acting like an outsider. It has established a structural bridge that deviates from the project's standard connectivity."

---

## ✅ The "Green Light" (Nominal Topology)
**The Setup:** You install a standard, well-integrated tool like `Vite` or `Tailwind`.

*   **Mathematical Signal:** **Smallest Partition > 40%** and **Robust Connectivity Score**.
*   **The Math Result:** These tools are "chatty." They share dependencies with Astro, Hono, and React. They are part of the **Mainland**. The math cannot find a clean way to "snap" them off because they are so deeply woven into the web.
*   **Real World Meaning:** "This tool is part of the community. It shares resources, shares sub-dependencies, and its execution power is transparent and connected."
