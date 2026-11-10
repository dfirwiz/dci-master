# DCI Master

Bilingual DCI learning website for `dfirwiz/dci-master`.

Public-source DCI overview and detailed Snort, Zeek and Arkime guides in English and Korean. The three tool guides cover 43 teaching sections with diagrams, tables, configuration walkthroughs, evidence interpretation, troubleshooting, capacity planning, review answers and primary-source references. Checked on 6 November 2026. These are public educational materials, not approved Defence baselines or procedures.

## Included

- English by default, with a Korean interface button; language selection is remembered locally.
- Home, Lessons, and Resources views linking the overview and all three tool guides.
- Responsive sidebar and keyboard-accessible navigation.
- DCI overview linked from Home, Lessons and its own navigation entry.
- Print / Save PDF button and a site-wide A4 print stylesheet: current language, no navigation, grayscale diagrams, readable tables and full reference URLs.
- Static HTML, CSS and JavaScript, with no framework or package installation.
- Five authentic tool/ecosystem screenshots, with source, historical version and execution limits stated in captions. See [ASSETS.md](ASSETS.md) for attribution.
- Two synthetic training PCAPs, a Snort teaching rule, a manifest with SHA-256 hashes and instructions. They use documentation addresses and `training.example`.
- Fundamentals page (English and Korean): TCP flags, the handshake and FIN/RST behaviour, port-state replies, connection states, scan and flood patterns, Wireshark filters, Snort 2 flag rules, essential ports, SMB named pipes with UTF-16LE content and RPC UUIDs, and snort.conf port variables.
- Snort chapter section 15: applying a Snort 2.9 rule (`local.rules`, `snort -T`, PCAP tests, live tests, service restart and a no-alert checklist).
- Three further synthetic PCAPs (`dci-smb-samr.pcap`, `dci-smb-samr-badsum.pcap`, `dci-tcp-flags.pcap`) with matching Snort 2 rule files.

## Files

`dist/` contains the deployable website. `.openai/hosting.json` contains its Sites deployment configuration.

## Preview

Serve `dist/` using a static HTTP server, for example `python -m http.server 8000 --directory dist`, then open `http://localhost:8000`.

The overview lives in `dist/overview.js`; the Fundamentals page lives in `dist/fundamentals.js`; the three tool guides live in `dist/chapters-data.js` and render through `dist/chapter-view.js`. GitHub Pages publication is automated as described below. The separate ChatGPT Sites deployment still uses the Sites workflow.

## GitHub Pages

Public URL: https://dfirwiz.github.io/dci-master/

The workflow in [`.github/workflows/pages.yml`](.github/workflows/pages.yml) uploads only `dist/` to GitHub Pages. It runs when `main` receives changes under `dist/` or to the workflow itself, and can also be started manually from Actions → Deploy DCI Master to GitHub Pages → Run workflow.

Repository Settings → Pages → Build and deployment → Source must be set to **GitHub Actions**. No separate build, framework installation, duplicated `docs/` directory or personal access token is needed.

The existing ChatGPT Sites URL is a separate deployment. Updating one host does not automatically update the other host; GitHub Pages follows the repository workflow, while ChatGPT Sites uses its own publishing process.

## Verification and limits

Verified all three guides in both languages, navigation and language persistence, mobile layouts at six viewport widths, SVG text bounds, screenshot loading, downloadable fixtures and six A4 print renders. Independently checked the synthetic PCAP packet lengths and checksums. Snort, Zeek and Arkime engines were not available on the authoring computer: commands and expected outcomes are teaching examples, not reported engine executions. The Zeek Playground screenshot shows the editor before a verified successful run. Snort's screenshot shows Splunk searching Snort alerts, not a native Snort graphical interface.

Update of 10 November 2026: the Fundamentals page and Snort section 15 were checked on Linux with Snort 2.9.20 (Ubuntu 24.04 package), tcpdump and TShark 4.2.2. Their tcpdump, Wireshark-filter and Snort outputs are copied from real runs against the three new synthetic PCAPs and against `dci-winrm.pcap` (two alerts, as the Snort 3 exercise predicts). Service restarts, `ping` and `tcpreplay` were not executed, and the netstat listing is illustrative; the pages say so where they appear.

Design update of 10 November 2026: the site uses self-hosted fonts under `dist/assets/fonts` — IBM Plex Sans for English text, Pretendard for Korean text and JetBrains Mono (ligatures off) for commands and code. All three are licensed under the SIL Open Font License 1.1; each folder contains its licence. Printing: the toolbar button prints the whole page; the printer icon beside each section heading prints that section only. Printed pages carry the lesson title, language, print date and page URL at the top and page numbers at the bottom (page numbers need a Chromium-based browser). Code blocks have a copy button on screen, and the table of contents follows your reading position on wide screens.

Cheat sheet (10 November 2026): `dist/cheatsheet.js` adds a quick-reference page with copy-ready Snort 2 commands for applying and testing rules, setting `HOME_NET` and `EXTERNAL_NET` (including tested results for common settings and errors), rule syntax, alert fields and a no-alert checklist. Commands were run with Snort 2.9.20 except the service commands and the Snort 3 snippet, which are marked as not run.

