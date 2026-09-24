# Changelog

All notable changes to `nm-portable` are documented here.

## v0.1.8 — 2026-09-24

- Added release-history documentation and repository-contract coverage so published downloads, checksums, CI, CodeQL, and license links remain visible from the source tree.

## v0.1.7 — 2026-09-24

- Modernized package license metadata to the current SPDX string form.
- Declared packaged license files explicitly and raised the setuptools build floor accordingly.
- Added packaging metadata regression coverage.

## v0.1.6 — 2026-09-18

- Preserved NetworkManager `cloned-mac-address` special values such as `preserve`, `permanent`, `random`, `stable`, and `stable-ssid` instead of treating them as hardware pins.

## v0.1.5 — 2026-09-18

- Expanded plaintext secret-field detection for exported NetworkManager keyfiles.
- Bumped the package version for the expanded audit surface.

## v0.1.4 — 2026-09-13

- Added standalone `.pyz` build coverage and release artifacts.
- Added smoke checks for the generated archive.

## v0.1.3 — 2026-09-13

- Improved CLI/test coverage around audit and fix behavior.

## v0.1.2 — 2026-09-12

- Refined README usage and safety documentation.
- Added project media links for screenshots and demo assets.

## v0.1.1 — 2026-09-11

- Added bilingual documentation and initial repository-quality checks.

## v0.1.0 — 2026-09-10

- Initial release: audit NetworkManager `.nmconnection` files and write portable copies with hardware-specific bindings removed.
