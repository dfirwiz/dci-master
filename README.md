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

The overview lives in `dist/overview.js`; the three tool guides live in `dist/chapters-data.js` and render through `dist/chapter-view.js`. GitHub Pages publication is automated as described below. The separate ChatGPT Sites deployment still uses the Sites workflow.

## GitHub Pages

Public URL: https://dfirwiz.github.io/dci-master/

The workflow in [`.github/workflows/pages.yml`](.github/workflows/pages.yml) uploads only `dist/` to GitHub Pages. It runs when `main` receives changes under `dist/` or to the workflow itself, and can also be started manually from Actions → Deploy DCI Master to GitHub Pages → Run workflow.

Repository Settings → Pages → Build and deployment → Source must be set to **GitHub Actions**. No separate build, framework installation, duplicated `docs/` directory or personal access token is needed.

The existing ChatGPT Sites URL is a separate deployment. Updating one host does not automatically update the other host; GitHub Pages follows the repository workflow, while ChatGPT Sites uses its own publishing process.

## Verification and limits

Verified all three guides in both languages, navigation and language persistence, mobile layouts at six viewport widths, SVG text bounds, screenshot loading, downloadable fixtures and six A4 print renders. Independently checked the synthetic PCAP packet lengths and checksums. Snort, Zeek and Arkime engines were not available on the authoring computer: commands and expected outcomes are teaching examples, not reported engine executions. The Zeek Playground screenshot shows the editor before a verified successful run. Snort's screenshot shows Splunk searching Snort alerts, not a native Snort graphical interface.
