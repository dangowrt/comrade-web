# comrade-web

The landing page and web tooling for **https://comrade.makrotopia.org/** — kept out of
the main [`comrade`](https://github.com/dangowrt/comrade) repository so that stays clean.

## What's here

```
index.html                     the landing page (banner, install, demo)
assets/
  asciinema-player.min.js      vendored asciinema-player, pinned to v3.17.0
  asciinema-player.css
  comrade-demo.cast            the terminal recording shown on the page (REDACTED)
tools/
  redact_cast.py               strip IPs / tokens / user+host from a .cast
.nojekyll                      serve assets verbatim (no Jekyll processing)
```

## How it reaches the site

`comrade.makrotopia.org` is a GitHub Pages site owned by the `comrade` repo, which also
serves the signed apt repository at the same origin. On every release, comrade's
`release.yml` **fetches this repo** and copies `index.html` + `assets/` into the Pages
deploy (substituting the current version into `__COMRADE_VERSION__`), alongside `dists/`
and `pool/`. So a push here is picked up on the next comrade release; to publish a page
change immediately, re-run comrade's release `publish` job.

## Updating the demo recording

1. Record a session (use throwaway / placeholder data where you can — see the note in
   `tools/redact_cast.py`):
   ```
   asciinema rec comrade-demo.raw.cast
   ```
2. Redact anything sensitive (IP addresses, session tokens, your user/host):
   ```
   python3 tools/redact_cast.py comrade-demo.raw.cast -o assets/comrade-demo.cast \
       --user "$USER" --host "$(hostname)" --extra makrotopia.org
   ```
   It exits non-zero and warns if a value survived split across recording events — fix
   those before publishing.
3. **Play `assets/comrade-demo.cast` back and confirm nothing leaked**, then commit it.

## Bumping the player

The player is vendored (not a CDN) to avoid third-party dependencies/tracking. To update:
```
V=3.17.0
base="https://github.com/asciinema/asciinema-player/releases/download/v$V"
curl -sSLo assets/asciinema-player.min.js "$base/asciinema-player.min.js"
curl -sSLo assets/asciinema-player.css    "$base/asciinema-player.css"
```
