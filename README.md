# DCI Master

Bilingual website scaffold for `dfirwiz/dci-master`.

This initial version contains interface structure only. No DCI lessons, operational procedures, training materials, or sample investigations have been added.

## Included

- English by default, with a Korean interface button; language selection is remembered locally.
- Home, Lessons, and Resources views with honest empty states.
- Responsive sidebar and keyboard-accessible navigation.
- Static HTML, CSS and JavaScript, with no framework or package installation.

## Files

`dist/` contains the deployable website. `.openai/hosting.json` contains its Sites deployment configuration.

## Preview

Serve `dist/` using a static HTTP server, for example `python -m http.server 8000 --directory dist`, then open `http://localhost:8000`.

Content can be added later without changing the initial navigation. Hosting publication uses the Sites workflow; pushing to GitHub alone does not automatically deploy this site.
