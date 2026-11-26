# snitch — status, plan, TODO

Handoff file: read this first in a new session. Usage, architecture and specs: `DOCUMENTATION.md` (update it with every change).

## What we are making

An **OSINT workbench** (C++20) on the user's own UI library **kitui** (`~/Desktop/projects/kitui`, immediate mode, linked with `add_subdirectory(../kitui)`). Enter a target, snitch detects its type, runs every enabled module for that type in parallel, and lists findings grouped by module. Values worth following (emails, usernames, phones found along the way) get a **Pivot** button.

Target types: **phone, email, IP, username, domain**. Search-engine **dorking** is a core feature, not an add-on.

## Hard decisions (user-set — do not change without asking)

- **UI: kitui only.**
- **Sources default to free/keyless.** Keyed or paid sources must be opt-in.
- **Dorking has a "use all search engines" checkbox** (off: engines that tolerate automation; on: adds Google, Bing, Yahoo, Yandex, Presearch, Baidu).
- **Dork backend: self-hosted SearXNG** (Docker, approved), with direct DuckDuckGo/Bing scraping as the fallback.
- **Phone: get as much as possible**, including past addresses and linked emails. The free route is people-search dorks, snippet extraction, and browser links. We don't scrape people-search sites behind Cloudflare.
- **Linux first. Windows build later** (decided 2026-11-24). Keep code portable; Linux-only spots are listed under Windows below.
- **libphonenumber** (system package) for phone parsing (the user left this to me; chosen because it gives the most information).
- **Hard-to-undo changes:** survey, show a plan, wait for the user's "go".

## Build / run / test

```sh
cd ~/Desktop/projects/mark47
cmake -S . -B build -G Ninja && cmake --build build
ctest --test-dir build --output-on-failure        # offline: detection, parsing, scrapers, WMN rule
./build/snitch [target]
KITUI_SHOT=out.ppm KITUI_SHOT_FRAMES=900 KITUI_MOUSE=768,16 KITUI_CLICK=1 ./build/snitch <target>   # scripted run + screenshot
```
Screenshot gotcha: the tiling WM resizes the window after start (it was 946×512 here, not 1280×760), and the scripted click happens at frame 5. Take a plain screenshot first to find coordinates.

## Done
- [x] Request HTML for Stripchat public profiles and surface HTTP 406 explicitly.
- [x] Keep direct and bundled checks under Social profiles, with external CSV results labeled separately.
- [x] Include the enabled WhatsMyName browser link on every username run.
- [x] Default to the external WhatsMyName fallback and identify public profile requests with an app User-Agent.
- [x] Add an optional external WhatsMyName.app fallback under Modules.
- [x] Bundle the full WhatsMyName roster and run its public profile checks inside Social profiles.
- [x] Add Cash App public Cashtag checks.
- [x] Add Solo.to and Carrd profile URL checks.
- [x] Add SoundCloud and seven more public URLs to the direct Social profiles checks.
- [x] Normalize spaced usernames and show potential hits from direct public social profile URLs.
- [x] Add public SoundCloud and Spotify username search and automatic track credits via Run.
- [x] Support authorized search proxy lists with connection-only failover.
- [x] Generate public-search queries by target type and show potential hits in a dedicated Auto dorking section.
- [x] Add optional offline original-carrier lookup and a libphonenumber prefix-data importer.
- [x] Add public phone-to-profile matches with account identifiers and source links across 20 services.
- [x] Group and clean up findings by run and source, with expandable duplicate links and GitHub profile tabs.
- [x] Rename the GUI program to `snitch` and its executable to `snitch`.

### Foundation ✅ (2026-11-24)
CMake project on kitui, `mark47_core` (UI-free library) + app + tests.

### Phase 1: core infrastructure ✅
Target type detection + manual override, `Module`/`Job` interface, libcurl HTTP layer (http(s) only, per-host rate limit, session cache, 8 MB cap, Stop aborts in flight), nlohmann/json vendored (3.12.0), worker threads + Stop, findings grouped by module with Copy/Open/Pivot, filter, "hide weak", JSON export, settings persisted.

### Phase 2: dorking ✅
SearXNG backend with the all-engines checkbox; DuckDuckGo (+ Bing) direct fallback; templates and lookup links in `data/dorks.json`; relevance check (weak results hidden); email/phone extraction from relevant snippets → pivots; a "run it yourself" Google link for every query that yields nothing new.

### Phase 3: IP ✅
Reverse DNS (DoH), RDAP (+ contact emails as pivots), ASN (RIPEstat), Shodan InternetDB, Tor exit list, ip-api geo.

### Phase 4: username + email ✅
WhatsMyName (691 sites, 16 parallel, ~33 s, 0 false hits on a random name), GitHub (+ commit emails), Reddit, Hacker News, Lichess, Chess.com, Keybase, Bluesky, Mastodon, Wayback. Email: MX/provider/SPF/DMARC/verification TXT, disposable list, Gravatar, keys.openpgp.org, GitHub commit search, username candidates.

### Phase 5: phone + pivots ✅
libphonenumber info (validity, formats, country, line type, area), 12 phone dorks (people-search, caller reports, social, docs, pastes, listings), people-search lookup links, Pivot buttons everywhere.

## Next

### Major OSINT roadmap

1. [ ] **Evidence review and source comparison.** Stable evidence IDs, search context, observation times, match labels, review states and notes landed. Reports share citations for the same URL. Remaining: identify syndicated copies across different URLs and distinguish their provenance from independent sources.
2. [x] **Local cases, pivot history and reports.** Save and reopen a case from an owner-only local case file. Record the exact finding that triggered a pivot and offer a timeline and source-linked report. Preserve existing JSON exports. A public profile handle can be pivoted, and its source survives a reopen. A report includes the source citations, targets and review notes.
3. [x] **Domain and organization research.** Add explicit domain targets and show RDAP, DNS, mail posture, and public certificate and archive history. Trace each alias or renamed domain to its source and timestamp. Acceptance: a domain with privacy-redacted RDAP remains usable and a historical association is clearly dated.
4. [ ] **Provider coverage and repeatability.** Coverage tracking and offline comparison of saved findings landed. Remaining: explicit capture and offline replay of raw provider responses.
5. [x] **Phone investigation triage.** Put number validity, line type, original carrier, public profile evidence and conflicting links in one summary. Surface the carrier dataset's version and missing coverage. Acceptance: a ported number, a recycled number, or a stale snippet cannot be summarized as verified ownership from prefix or search-index evidence alone.

### Domain research and case comparison release

- [x] **Passive Domain targets.** DNS, domain RDAP, mail posture and bounded public certificate/archive history are available with dated evidence and typed pivots.
- [x] **Coverage-aware case comparison.** The Compare pane distinguishes changed, seen, new, absent and unknown evidence. A saved case can be reopened to replay its comparison offline.
- [x] **Source provenance.** Evidence details link matching URLs, archive originals, registry redirects, provider-supplied canonical URLs and matching text. Matching text alone leaves origin unconfirmed.
- [x] **Phone evidence summary.** Phone runs show carrier metadata, gaps, dated profile leads and conflicting observations. Current ownership and current carrier remain unknown from these sources.

Validation still open: run the live domain providers and loopback suite from a network-enabled terminal. Capturing raw provider responses for offline parser replay is a separate follow-up.

### Improvement plan (Codex handoff, 2026-11-24)

1. [x] **Establish a repeatable Linux baseline.** Add a core-only CMake option that configures without kitui/SDL and keeps the default GUI build. Exercise both configurations from fresh build directories, retain the offline parser tests and add a GUI smoke check for Run, Stop and export. Record the kitui revision used. Pin or package dependencies after a release workflow is agreed.
2. [x] **Preserve run provenance and make exports reliable.** Assign each launch a run ID with target, type and outcome. Give findings and pivots their originating run. Add an export schema version while retaining existing fields where their meanings still apply. Make writes atomic, collision-safe and owner-only by default. Report real write failures. Verify with synthetic data that A → B exports attribute each finding correctly even if the input is edited, and that a failed write leaves a prior export intact. Apply the same atomic write pattern to settings.
3. [ ] **Bound transport state and verify Stop.** Implementation and fixture landed. Run the loopback suite where TCP sockets are permitted. Cap in-memory cache bytes and entries, give entries a TTL, and bypass shared caching for credentialed requests or responses that depend on custom headers. Ensure canceled jobs do not leave unnecessary rate-limit reservations. Test timeouts, cancellation, cache behavior, redirects and the 8 MiB cap with a loopback fixture. Confirm timings before documenting a Stop latency guarantee.
4. [x] **Make search failures diagnosable with offline fixtures.** Distinguish empty results, blocking/rate limiting, transport errors and malformed or misconfigured SearXNG responses. Honor provider limits and stop contacting a provider after explicit blocks during that run. Keep browser links available when results are unavailable or empty. Proxy rotation was raised in the prior handoff. This milestone uses provider-aware failure handling and the existing manual fallback.
5. [x] **Profile kitui, then expand.** Measure frame time with synthetic findings before virtualizing rows or changing lock scope. Check kitui font support using a recorded revision. Defer new providers, CLI and Windows work until the run model and export schema stabilize.

For each implemented item, check it off here and add a dated entry to the [change log](DOCUMENTATION.md#11-change-log) with behavior, files, verification results and remaining gaps.

### Data quality
- [ ] Integrate live WhatsMyName API results if the provider supplies a supported endpoint and response schema.
- [ ] Smoke-test public SoundCloud and Spotify search coverage and automatic MusicBrainz credits against live sources.
- [ ] Run the authorized proxy loopback tests on a host with IPv4 socket access.
- [ ] Smoke-test Auto dorking with a configured SearXNG instance and synthetic targets.
- [ ] Import and verify the upstream carrier dataset on a network-enabled host. The offline path passed with synthetic metadata.
- [ ] Check the FastPeopleSearch URL format in `data/dorks.json` in a browser. The other lookup links were checked on 2026-11-25.
- [ ] Mastodon: only mastodon.social is checked. Accept `user@instance` handles.
- [ ] Reddit: blocked without OAuth. Add opt-in OAuth app credentials.
- [ ] Full profile catalog: category filter (e.g. hide NSFW) and a "known" self-test (each site's `known` accounts must hit).
- [ ] GitHub: optional token (60 → 5000 req/h; commit search 10 → 30/min).
- [ ] Select a bundled or configured font for glyphs outside the default kitui atlas if supported languages require it.

### Features
- [ ] Assess user-authorized data import for registration evidence. Public indexing alone cannot establish registered numbers.
- [ ] Discord: verify the username check with a real token (only a fake-token 401 was confirmed on 2026-11-25).
- [ ] Opt-in keyed sources: HIBP, Shodan full, Censys, AbuseIPDB, GreyNoise, VirusTotal, ipinfo, Brave Search API. Store keys outside the repo (`~/.config/mark47/keys.json`, mode 600).
- [ ] CSV export; headless `--cli` mode (JSON lines on stdout) for scripting.
- [ ] Revisit disk caching only if a bounded memory cache proves insufficient. Decide what target data may persist and for how long first.
- [ ] Virtualize findings rows. The 4,000-row offscreen profile measured 21.83 ms median and 31.04 ms p95 per frame. Repeat the same benchmark after the change.
- [ ] Workers: finished threads are joined only on the next Run. Fine for now.

### Windows (later, per user)
Linux-only today: libcurl/OpenSSL/libphonenumber from system packages (need MinGW builds or vcpkg), `arpa/inet.h` (`inet_pton` → ws2tcpip + `WSAStartup`), `posix_spawnp("xdg-open")` → `ShellExecuteW`, settings path (`XDG_CONFIG_HOME` → `%APPDATA%`), `MARK47_DATA_DIR` baked to the source tree (ship `data/` next to the .exe).

### Housekeeping
- [ ] Confirm repository ownership and intended remote before initializing Git. This workspace exposes an empty, read-only `.git` directory.
- [ ] kitui comes from a local path (`shortcut:` in CMakeLists); switch to FetchContent with a pinned commit when builds must be reproducible.
