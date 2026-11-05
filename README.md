# DCI Master

Bilingual website scaffold for `dfirwiz/dci-master`.

This version adds a public-source DCI overview in English and Korean, with original teaching examples, diagrams, review answers and references. It does not reproduce restricted Defence procedures.

## Included

- English by default, with a Korean interface button; language selection is remembered locally.
- Home, Lessons, and Resources views with honest empty states.
- Responsive sidebar and keyboard-accessible navigation.
- DCI overview linked from Home, Lessons and its own navigation entry.
- Print / Save PDF button and a site-wide A4 print stylesheet: current language, no navigation, grayscale diagrams, readable tables and full reference URLs.
- Static HTML, CSS and JavaScript, with no framework or package installation.

## Files

`dist/` contains the deployable website. `.openai/hosting.json` contains its Sites deployment configuration.

## Preview

Serve `dist/` using a static HTTP server, for example `python -m http.server 8000 --directory dist`, then open `http://localhost:8000`.

The bilingual article lives in `dist/overview.js`. Additional content can be added later. Hosting publication uses the Sites workflow; pushing to GitHub alone does not automatically deploy this site.
