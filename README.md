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

## Files

`dist/` contains the deployable website. `.openai/hosting.json` contains its Sites deployment configuration.

## Preview

Serve `dist/` using a static HTTP server, for example `python -m http.server 8000 --directory dist`, then open `http://localhost:8000`.

The overview lives in `dist/overview.js`; the three tool guides live in `dist/chapters-data.js` and render through `dist/chapter-view.js`. Hosting publication uses the Sites workflow; pushing to GitHub alone does not automatically deploy this site.

## Verification and limits

Verified all three guides in both languages, navigation and language persistence, mobile layouts at six viewport widths, SVG text bounds, screenshot loading, downloadable fixtures and six A4 print renders. Independently checked the synthetic PCAP packet lengths and checksums. Snort, Zeek and Arkime engines were not available on the authoring computer: commands and expected outcomes are teaching examples, not reported engine executions. The Zeek Playground screenshot shows the editor before a verified successful run. Snort's screenshot shows Splunk searching Snort alerts, not a native Snort graphical interface.
