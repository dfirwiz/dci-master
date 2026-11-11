# Screenshot attribution and training data

The site distinguishes authentic screenshots from original diagrams and synthetic training traffic. Screenshots are not evidence of an organisational deployment or successful local engine execution. Source and version notes appear beside each image in both languages.

## Snort alert search in Splunk

- File: `dist/assets/screenshots/snort-alerts-splunk.png`
- Author: Noah Dietrich.
- Source: *Snort 3.1.18.0 on Ubuntu 18 & 20: Configuring a Full NIDS & SIEM*, 30 December 2021, page 20 (zero-based PDF page 19).
- [Original PDF](https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/012/147/original/Snort_3.1.8.0_on_Ubuntu_18_and_20.pdf), listed through [Snort documents](https://snort.org/documents).
- License: [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/), stated on page 3 of the guide. This license applies to the reproduced image; no whole-project license is asserted here.
- The original embedded PNG was extracted without cropping, redrawing or pixel changes. SHA-256: `980296c06d3af964fe8b167f7ebc40804aca51fd7a813c463c9d5e0a8d541492`.
- This historical screenshot shows Splunk Search & Reporting with a Snort JSON alert query. No returned alerts are visible. The exact Splunk version is not stated. More provenance is in `snort-alerts-splunk-source.json`.

## Arkime official screenshots

- `arkime-sessions.webp`: [original](https://arkime.com/assets/sessions.png).
- `arkime-session-detail.webp`: [original](https://arkime.com/assets/session-detail.png).
- `arkime-spiview.webp`: [original](https://arkime.com/assets/spiview.png).
- Source: [Arkime official screenshot collection](https://arkime.com/#screenshots). Images are reproduced for teaching with attribution to the Arkime project. Sessions and SPI View headers display v5.0.0; these historical screens are not presented as the current installed version. Local WebP previews are resized to 1400 pixels wide and compressed for web delivery; full-size links open the official original PNGs. No additional license is asserted for these third-party images.

## Zeek Playground

- File: `dist/assets/screenshots/zeek-playground.png`.
- Actual browser capture of the [official Try Zeek Playground](https://try.zeek.org/), 6 November 2026. The interface displayed Zeek 9.0.1 with the built-in `http.pcap` example selected.
- This is a hosted editor screen, not a native Zeek GUI. A successful analysis result was not verified for this screenshot; it illustrates controls before execution.

## Original teaching assets

SVG diagrams and bilingual explanations were created for this site. The PCAP fixtures in `dist/assets/labs/` were generated as synthetic teaching examples, using documentation IP addresses and `training.example`. See that directory's README and manifest for packet contents, fixed capture times, limits and hashes. There are no captured operational network records in these fixtures.
