# Personal desktop build

This fork (`pkral78/paseo`) builds its own ad-hoc signed macOS app. It does not exist upstream; never open a pull request to `getpaseo/paseo` with anything described here.

## Branches and remotes

- `personal/desktop` is the fork's default branch: an upstream release tag plus the personal commits. Dependabot reads only the default branch, which is why it is not `main`.
- `main` mirrors upstream. Keep personal commits off it.
- In the usual checkout, `origin` is the fork and `github` is upstream, and `gh` resolves to upstream. Pass `-R pkral78/paseo` to `gh`, and push only to `origin`.
- A push to any `personal/**` branch runs a full DMG build. Put daemon or feature work on another prefix.

## Signing

Build with `-c.mac.identity=- -c.mac.hardenedRuntime=false -c.mac.notarize=false`.

The hardened runtime enforces library validation: every loaded library must carry the app's Team ID. An ad-hoc signature has none, so dyld kills the app at launch with `mapping process and mapped file (non-platform) have different Team IDs`.

GitHub's hosted macOS runners do not enforce library validation. The packaged-app smoke passes there on a build that cannot start on a normal Mac. After any change to signing, download the DMG and launch it on a real machine.

Fetch artifacts with `gh run download -R pkral78/paseo -n paseo-desktop-arm64`. A browser download is quarantined and Gatekeeper rejects ad-hoc apps.

## Updates

The workflow sets `publish.owner` to the fork. With upstream's value the app downloads official Developer ID builds, which an ad-hoc app cannot install. The fork publishes no releases, so update checks log `No published versions on GitHub` and the app never prompts.

To move to a new upstream release, rebase `personal/desktop` onto the tag and push. Regenerate the lockfile changes with `npm` instead of merging `package-lock.json` by hand.

## Dependency advisories

`.github/scripts/audit-shipped.cjs` fails the build on a high or critical advisory in a package packed into the app. `npm audit` cannot gate the build: it also counts the website, Expo tooling and test runners. The script cannot see packages Metro bundles into the web UI.

Accepted advisories are listed by GHSA id in that script, each with its reason. Two constraints behind them:

- `zod` stays on 4.4.x. 4.6 changes inferred schema types and `packages/client` stops compiling.
- `ai` stays on 5.0.78. Later 5.x releases pull in `undici` 5, which has advisories of its own.

Never run `npm audit fix --force`. Root `overrides` pin the Expo SDK, and several packages carry patches in `patches/` tied to exact versions.

## Building the daemon

The default branch does not affect local builds. `npm run dev` keeps state in `.dev/paseo-home`; the installed app's daemon uses `~/.paseo` on port 6767, and both run side by side. See [development.md](development.md). Build from `personal/desktop` when you want the daemon with the same dependency fixes as the app.
