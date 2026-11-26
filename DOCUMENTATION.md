# snitch documentation

snitch is an OSINT workbench built on [kitui](../kitui). Give it a phone number, email address, IP, username, domain, or Spotify track URL: it detects the type, runs every enabled module for that type in parallel, and lists what it finds by run and source. Values worth following up get a **Pivot** button that makes them the next target.

> Kept up to date with every change. Status and plans: `TODO.md`.

---

## Contents
1. [Build and run](#1-build-and-run)
2. [Using the app](#2-using-the-app)
3. [Target detection](#3-target-detection)
4. [Modules](#4-modules)
5. [Dorking](#5-dorking)
6. [Settings, files, export](#6-settings-files-export)
7. [Architecture](#7-architecture)
8. [Writing a module](#8-writing-a-module)
9. [Testing](#9-testing)
10. [Limitations](#10-limitations)
11. [Change log](#11-change-log)

---

## 1. Build and run

Linux only for now. Needs CMake ≥ 3.24, Ninja, a C++20 compiler, SDL3, libcurl ≥ 7.85, OpenSSL and libphonenumber:
```sh
sudo pacman -S sdl3 curl openssl libphonenumber     # Arch
cd ~/Desktop/projects/mark47
cmake -S . -B build -G Ninja && cmake --build build
ctest --test-dir build --output-on-failure
./build/snitch [target]                              # optional target pre-fills the field
```
Use `-DMARK47_BUILD_GUI=OFF` to configure and build the core and tests without kitui or SDL3. Python 3 enables the loopback HTTP suite.

kitui is expected at `../kitui`; point elsewhere with `-DKITUI_DIR=/path`. nlohmann/json 3.12.0 is vendored in `third_party/nlohmann` (MIT).

### SearXNG (recommended)
Dorks work best through a local SearXNG. Without it snitch scrapes DuckDuckGo directly, plus Bing when "use all search engines" is on, and those block within a few runs (§5).
```sh
mkdir -p ~/.config/searxng
docker run -d --name searxng -p 127.0.0.1:8888:8080 -v ~/.config/searxng:/etc/searxng searxng/searxng
```
Then edit `~/.config/searxng/settings.yml` (created on first start):
```yaml
search:
  formats: [html, json]   # required: without json mark47 gets HTTP 403
server:
  limiter: false          # local, single user
```
`docker restart searxng`. The address is set in snitch's Settings (default `http://127.0.0.1:8888`).

---

## 2. Using the app

| Area | What it does |
|---|---|
| **Target** + type dropdown | Type a target. `Auto` detects the type (shown in green, or "unknown type" in red); pick a type to override, e.g. for an all-digit username |
| **Run / Stop** | Run starts every ticked module that fits the type. While running the button becomes **Stop**, which requests cancellation. Rate-limit waits check about every 50 ms. In-flight cancellation depends on libcurl progress callbacks |
| **Export** | Writes findings, runs and log to `mark47_<timestamp>_<sequence>.json` in the working directory |
| **Clear** | Empties the current workspace when it is idle |
| **Save case** / **Open case** | Save a local case snapshot or reopen the file entered in **Case file** |
| **Report** | Writes a Markdown timeline, evidence list, notes and source citations to the working directory |
| **Settings** (top bar) | Opens a panel for optional credentials. It currently holds a Discord user token. **Back** returns to Findings |
| **Details** | Inspect a finding’s evidence record, copy its fields, set review status and add a note |
| **Modules** | Checkboxes for the modules that accept the current type. Hover for a description. Choices are remembered |
| **Settings** (left column) | "Dorks: use all search engines", "Full profile catalog", SearXNG URL, default phone region |
| **Filter** | Matches source, label, value, or URL in any visible member of a group (case-insensitive) |
| **Hide weak** | Hides dork results that don't mention the target (on by default) |
| **Findings** | Newest run first, then by source. Rows offer **Copy**, **Open**, or **Pivot** where applicable. **+N related** reveals grouped hits and their original links. |
| **Log** | Module status, errors, blocked engines. Follows new lines |

Each run groups exact repeat rows, findings with the same link, and identical pivot values. GitHub profile tabs appear with the account’s main profile, while repository, issue, and other distinct page paths retain individual rows. Expand **+N related** to see distinct source labels, snippets and URLs. Copy and Open on a grouped GitHub profile use the canonical account URL. The related rows keep their own links. Display text collapses whitespace and shortens long lines to fit. Filtering can surface a group by a related row’s text.

A run never clears earlier findings, so pivots accumulate in one list. Use Clear to start over. Export uses the last launched target and includes accumulated findings. Each finding carries its originating run ID. Export includes the original rows before display grouping. Launching from a Pivot records the parent run while the target still matches the selected finding.


### Case workspace

Use **Details** to inspect the evidence ID, provider, observed time and match basis. Search findings also show their query and source URL when available. Review status is an analyst annotation. A run launched from **Pivot** records the exact evidence ID, and **Via E…** jumps back to its details.

**Save case** creates a new owner-only `mark47_case_*.case.json` in the working directory and places the path in **Case file**. Enter an existing case path and click **Open case** to continue it. A dirty workspace asks for confirmation before replacement, and a malformed case leaves the current workspace available. Save and Open are available between runs. The case format preserves evidence IDs, review notes, provider metadata, pivot ancestry and the log.

**Report** creates an owner-only `mark47_report_*.md` with targets, evidence, queries, notes and source citations. Repeated references to the same source URL share a citation. That count measures distinct URLs. Different URLs may still reflect the same upstream source. The existing **Export** button continues to write schema-v2 JSON.


### Compare runs and sources

Open **Compare** and choose an earlier and later run for the same target and type. The panel shows changed values, evidence seen again, new observations and recorded provider coverage. **Absent in recheck** requires explicit complete or empty coverage for the same data scope in both runs. A blocked, skipped, partial or older undocumented check leaves unmatched prior evidence at **Unknown coverage**. Capped search, certificate and archive results cannot establish absence. **First observed** marks a later-only finding when earlier coverage is incomplete.

Coverage is saved in the case. Reopen a saved case to repeat its comparison offline. The case contains normalized findings and coverage, while raw provider response replay remains a separate backlog item.

In **Details**, **Related sources** shows exact URL matches and recorded origins from archive metadata, provider-supplied canonical URLs or observed registry redirects. Matching excerpts are labeled **origin unconfirmed**. Both URLs and source dates remain inspectable.

---

## 3. Target detection

`detect()` in `src/util.cpp`, checked in this order:

| Type | Rule | Examples |
|---|---|---|
| IP | parses as IPv4 or IPv6 (`inet_pton`) | `8.8.8.8`, `2001:4860::8888` |
| Email | one `@`, something before it, a `.` after it, no trailing `.` | `a.b+tag@example.co.uk` |
| Phone | only digits and ` +-().`, 7–15 digits | `+1 (650) 253-0000`, `650.253.0000` |
| Spotify track | an `open.spotify.com/track/…` URL or `spotify:track:…` URI | `https://open.spotify.com/track/…` |
| Domain | a homepage URL with no path, or a bare domain selected with the **Domain** override | `https://example.org/`, `example.org` with override |
| Username | 1–64 of letters, digits, `._-`, optional leading `@` (stripped before running) | `torvalds`, `@torvalds` |

Username searches remove whitespace and one leading `@` or `$` before the run. For example, `@Ali ce` is checked as `Alice`. A digits-only username like `1234567` can detect as a phone. Select **Username** to override.

Phone numbers without a leading `+` are parsed as the **Region** setting (ISO country code, default `US`).

---

## 4. Modules

All modules are free and need no key. "Pivot" marks findings that get a Pivot button.

### Phone (`src/modules/phone.cpp`)
| Module | Source | Gives |
|---|---|---|
| Number info | libphonenumber (offline) | valid?, E.164 / international / national formats, country, line type (mobile, landline, VoIP, toll free…), area where the number was assigned, original carrier when prefix data is installed |

To install optional carrier data, run `python3 tools/import_carrier_data.py` from the project directory. The importer downloads the [libphonenumber v9.0.44 source release](https://github.com/google/libphonenumber/releases/tag/v9.0.44) and builds `data/carrier-prefixes.txt` from the English tables. Use `--archive /path/to/source.tar.gz` for local import. `MARK47_DATA` selects the data directory for both the app and importer.

**Original carrier** is the most specific matching prefix assignment. Coverage varies by country and number range. The row reports unavailable data or no matching prefix as appropriate. The app looks up numbers offline. Portability may change the current carrier.

Click **Phone summary** in a phone run heading or the case toolbar for the latest phone run. The summary brings number facts, the carrier dataset version and dates, coverage gaps, and dated public profile leads together. It flags multiple handles on one service and differing original-carrier or line-type observations for the same normalized number. Current carrier and account ownership remain unknown from prefix data or indexed hits.


Phone also gets **Dorks** and **Lookup links** (§5). Dorks prioritize **Public match** rows when an indexed result contains the exact normalized phone number and points to a recognized profile URL. Each row gives the service, the handle or account identifier from the URL, and an Open action. Recognized handles also appear as manual username pivots with the same source evidence. Expand related rows for the search snippet. A public match records evidence from the search index. It does not establish account ownership or private registration. Some snippets can be stale or refer to a third party.

The profile rules cover Facebook, Instagram, X, LinkedIn, TikTok, YouTube, Threads, Reddit, Bluesky, Mastodon (mastodon.social), GitHub, GitLab, Pinterest, Twitch, SoundCloud, Linktree, Medium, DEV Community, Behance and Dribbble. Coverage depends on indexed results and supported URL shapes. Login, signup and recovery endpoints are outside this feature.

### Email (`src/modules/email.cpp`)
| Module | Source | Gives |
|---|---|---|
| Mail DNS | Cloudflare DNS-over-HTTPS | MX records, mail provider (Google, Microsoft 365, Proton, filters…), SPF, DMARC, service verification TXT records (shows which SaaS the domain uses), domain (with RDAP link). No MX = can't receive mail |
| Disposable | disposable-email-domains list (GitHub) | throwaway domain yes/no |
| Gravatar | Gravatar API v3 (SHA-256 of the address) | profile, avatar, location, bio, job, verified linked accounts |
| PGP keys | keys.openpgp.org | published key (only addresses the owner verified) |
| GitHub commits | GitHub commit search (10/min unauthenticated) | commit count, GitHub user (pivot), commit author names, repos |
| Email pivots | local | username candidates from the local part (`first.last` → `firstlast`, `first_last`) (pivot); the `+tag`, which often names the site the address was given to |

### Username
| Module | Source | Gives |
|---|---|---|
| Social profiles | Direct URLs and the bundled `data/username-sites.json` catalog | **Potential account** rows with the site, handle and link. The direct checks cover 18 platforms including X, Instagram, Facebook, SoundCloud, Solo.to, Carrd and Cash App. The optional full catalog adds public checks across all categories. |
| WhatsMyName | WhatsMyName.app browser interface | External search link when enabled. |
| WhatsMyName (CSV) | CSV exported by WhatsMyName.app | Imported external hits. |
| SoundCloud | SoundCloud oEmbed | **Potential account** for a public profile supported by the embed response. |
| GitHub | GitHub REST (60 req/h unauthenticated) | profile fields, repos/followers, **commit emails** from the 3 most recently pushed own repos (pivot; noreply addresses skipped) |
| Reddit | `about.json` | created, karma, bio (usually blocked without OAuth: logged as an error) |
| Hacker News | Firebase API | created, karma, about |
| Lichess, Chess.com | public APIs | profile, real name, location, join/last-seen dates |
| Keybase | lookup API | name, bio, identity proofs (other accounts) |
| Bluesky | public AppView | `<name>.bsky.social` (or a full handle): name, bio, created, DID, counts |
| Mastodon | mastodon.social lookup | name, bio, created, profile fields |
| Discord | `pomelo-attempt` (undocumented, needs the user token saved under top-bar **Settings**) | **Username taken** or **Username available** for the lowercased handle. One request per run, no retries. Skipped without a token or for names Discord rejects (2–32 of `a–z 0–9 _ .`, no `..`). A 401, 429 or CAPTCHA response stops the check. No profile or user ID is returned. Automating a user account breaks Discord's terms and can get it banned |
| Wayback | Wayback Machine CDX | snapshot counts and first capture for the name on X/Twitter, Instagram, Facebook, TikTok, YouTube, GitHub, Reddit (deleted accounts show up here) |

The same name on two sites is **not** proof of the same person. Cross-check location, bio, links and avatars.

### IP (`src/modules/ip.cpp`)
| Module | Source | Gives |
|---|---|---|
| Reverse DNS | DNS-over-HTTPS PTR | hostname(s) |
| RDAP | rdap.org (redirects to the right registry) | network name/handle, range, country, contacts by role (name, address, phone; emails are pivots) |
| ASN | RIPEstat prefix-overview | announced prefix, AS number + holder (link to bgp.he.net) |
| Shodan InternetDB | internetdb.shodan.io | open ports, hostnames, tags, software (CPE), CVEs (links to NVD) |
| Tor exit | Tor Project bulk exit list | current exit node yes/no |
| Geo (ip-api) | ip-api.com (**plain HTTP**, non-commercial, 45/min) | city/region/zip/country (map link), timezone, ISP/org, mobile/proxy/hosting flags |

**Full profile catalog** is on by default. The local roster retains 691 entries from the archived WhatsMyName dataset. It has 686 runnable public GET checks, including 30 adapted to public profile URLs. Discord (User), twoplustwo, Wikimapia and Znanija are listed as unavailable because the original rules lack a usable public profile check. The upstream-disabled 7cup entry stays disabled. Existing installations that disabled WhatsMyName retain that preference through the new setting. No catalog download is needed to start a run. [Archived upstream dataset and license](https://github.com/WebBreacher/WhatsMyName)

Enable **WhatsMyName** under **Modules** to add the external web search to each username run. Use **Open** on its row to send the normalized handle to WhatsMyName.app in your browser. After the external run, export its found accounts as CSV. Click **Import WMN CSV** beside the matching username run and enter the file path. Imported hits appear under **WhatsMyName (CSV)** and are included in saved cases and reports. The toggle is on by default and saved separately from **Full profile catalog**. [OSINT Combine’s tool listing](https://www.osintcombine.com/free-osint-tools)

The worker pool uses up to 16 workers with the full catalog and four for the direct list. It reuses compatible overlapping requests and identifies itself as `snitch/1.0 (public profile lookup)` in its User-Agent. The log reports attempts, hits, blocks, unavailable checks and skipped catalog entries. Websites still need to be reachable for live results.

A **Potential account** is a lead that the public URL responded. Some platforms serve generic pages or hide profiles behind login. The same handle can belong to different people.

### Music profiles and Spotify credits (`src/modules/music.cpp`)

With a username target, the **SoundCloud** module checks the corresponding public profile through oEmbed. **Dorks** also searches indexed SoundCloud profiles and Spotify user, artist, and track pages. An exact Spotify user URL ID is labeled separately from an artist or track lead that mentions the name. Track leads can be pivoted into a track run. [SoundCloud oEmbed reference](https://developers.soundcloud.com/docs%2Foembed)

Enter a Spotify track URL or URI and click **Run**, or pivot from a track lead and run it. snitch gets the public track title and checks MusicBrainz for a recording linked to the exact Spotify URL. If that link is missing, it looks for an exact public title and artist match and uses it only when the result set contains one matching recording. These results are labeled for review.

**Spotify credits** in Findings lists roles such as songwriter, composer, lyricist, and producer when the linked MusicBrainz recording or work lists them. Each row links to the credit source and records the matching method. Spotify's documented track response supplies performer metadata. Automatic writer and production credits come from MusicBrainz and can differ from Spotify's distributor-supplied Credits panel. Credits can be incomplete and may use aliases or include collaborators. [Spotify Get Track](https://developer.spotify.com/documentation/web-api/reference/get-track) [Spotify Credits](https://support.spotify.com/is-en/artists/article/song-credits/) [MusicBrainz relationships](https://musicbrainz.org/doc/MusicBrainz_API#Relationships)

### Domain (`src/modules/domain.cpp`)

Use the **Domain** type for bare names, or enter an HTTP(S) homepage URL without a path to detect the type automatically. Dotted usernames retain their existing interpretation. Internationalized names can be entered in ASCII/Punycode form.

| Module | Coverage |
|---|---|
| Domain DNS | Current A, AAAA, CNAME, NS, MX, TXT, CAA, SPF and DMARC results. A/AAAA, aliases and mail hostnames can be pivoted. Mail provider is inferred from MX. |
| Domain RDAP | Public registry domain, registrar, statuses and available event dates. The evidence records the registry URL when the bootstrap service redirects. |
| Certificate history | Up to 24 dated names from public certificates matching the domain. Those names are historical observations. Check current DNS separately. |
| Domain archive | Up to 12 dated homepage captures, with the original URL recorded as evidence. |

Provider references include the [Cloudflare DNS response fields](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/), [RDAP bootstrap specification](https://www.rfc-editor.org/rfc/rfc9224), [crt.sh](https://crt.sh/), [Internet Archive CDX documentation](https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md).

### Phone, email, IP and username (`src/modules/dork.cpp`)
| Module | Gives |
|---|---|
| Dorks | generated public searches, template search results, and linked email/phone pivots from relevant template results. See §5 |
| Lookup links | pages to open in your browser: people-search and caller-ID sites (phone), ThatsThem/HIBP/Epieos (email), AbuseIPDB/VirusTotal/Shodan/Censys/GreyNoise (IP). **Never fetched** by snitch |

---

## 5. Dorking

### Auto dorking

With **Dorks** enabled, a run generates up to two public-search queries before the configured templates. The queries use the target type to look for public profiles, contact and directory pages, or IP network attribution. Phone queries use the normalized number and international formatting. Findings labels matching rows **Potential hit** under **Auto dorking**, with a title, snippet, search engine and source link when available. This section appears when there is a hit.

Each generated hit must contain the target as a distinct value in the result title or snippet. Phone hits require a full normalized number match. The section deduplicates identical URLs and displays up to 12 hits per run. The generated and template searches share the same provider limits and per-run block state. Potential hits represent search-index leads and require corroboration before drawing an identity conclusion.

### Backends
For each query, in order:
1. **SearXNG** at the configured URL with `format=json`. Engines:
   - default: `duckduckgo, brave, startpage`
   - **use all search engines**: adds `google, bing, yahoo, yandex, presearch, baidu`

   Engines SearXNG reports as unresponsive (CAPTCHA, timeout) are logged per query. If SearXNG is unreachable, returns an error, or sends malformed JSON, snitch logs why once and stops trying it for the rest of the run. HTTP 403 can indicate missing `json` in `search.formats` or an access restriction. HTTP 429 or a `Retry-After` header switches the rest of the run to manual search links.
2. **Direct scraping** (fallback): DuckDuckGo's HTML endpoint, plus Bing when all engines is on, at most one request per 4 s per engine. For either direct provider, HTTP 202, 403, 429, a `Retry-After` header, or a recognized challenge page pauses requests to that provider for the rest of the run. The log distinguishes these from failures and responses with no parseable results. Bing works but without cookies largely ignores `site:`/`OR`/quotes. Mojeek and Qwant deny scripted access (HTTP 403, also through SearXNG), so neither is requested.

Results from all engines are merged by URL. Each finding shows `title | snippet [engines]`.

### Authorized search proxies

To opt in, create `data/search-proxies.txt` (or put it in your `MARK47_DATA` directory). Add one proxy you control or are authorized to use per line, in preferred order. For example:

```text
# Replace these examples with your own endpoints.
http://proxy.example.test:8080
socks5h://backup.example.test:1080
```

Accepted schemes are `http`, `https` and `socks5h`, each with an explicit port. The list supports up to eight distinct endpoints, comments and blank lines. It rejects embedded credentials. Load errors appear in the Log.

The list applies to the DuckDuckGo and Bing fallback requests. SearXNG engine traffic uses SearXNG’s own configuration. The app checks connectivity while making normal search requests and stays on the first reachable proxy. It advances only on a definite proxy DNS or connection refusal before receiving a response. Provider blocks, rate limits, challenges and proxy authentication errors do not advance the list. Host request spacing still applies across all endpoints. If the list is invalid or exhausted, failed searches retain browser links.

### Relevance and extraction
Engines often ignore quotes, so each result is checked:
- phone: the national digits appear in the title/snippet digits (catches every formatting);
- email: the full address, or both the local part and the domain;
- username/IP: the target text (case-insensitive).

Results that fail are labelled **weak** (hidden by "Hide weak"). From relevant results only, snitch extracts email addresses and phone numbers (phones validated by libphonenumber and normalised to E.164) and lists new ones as **linked email / linked phone** pivots. For phone targets that's how names, relatives' numbers and emails surface from people-search snippets.

If a query yields **nothing new and relevant**, a finding with the query and a Google link is added, so you can run it in your browser.

### `data/dorks.json`
Read on every run; edit freely.
```json
{
  "phone":    [{"label": "people search", "q": "\"{dashed}\" (site:truepeoplesearch.com OR ...)"}],
  "email":    [...], "username": [...], "ip": [...],
  "links": {
    "phone": [{"label": "FastPeopleSearch", "region": "US", "url": "https://www.fastpeoplesearch.com/{dashed}"}],
    "email": [...], "username": [...], "ip": [...]
  }
}
```
Placeholders (values are inserted as-is; `*_url` ones are URL-encoded):

| Type | Placeholders |
|---|---|
| all | `{target}`, `{target_url}` |
| email | `{local}`, `{domain}` |
| phone | `{e164}` (+16502530000), `{intl}` (+1 650-253-0000), `{national}` ((650) 253-0000), `{dashed}` (650-253-0000), `{nat_digits}` (6502530000), `{digits}` (16502530000), `{region}` (US), `{national_url}`, `{e164_url}` |

A link with `"region"` is only shown for phone numbers from that country. Override the data directory with `MARK47_DATA=/path`.

---

## 6. Settings, files, export

| What | Where |
|---|---|
| Settings (SearXNG URL, region, all engines, disabled modules) | `~/.config/mark47/settings.json` (`$XDG_CONFIG_HOME` respected); loaded at start, saved on exit |
| Optional credentials (Discord user token) | `~/.config/mark47/keys.json`, mode 0600, written atomically on **Save token**. **Remove token** deletes the file |
| Dork templates + lookup links | `data/dorks.json` (source tree, or `~/.local/share/snitch` when installed; `MARK47_DATA` overrides) |
| Export | `./mark47_<timestamp>_<sequence>.json`, schema v2. See fields below. |

Schema v2 keeps the legacy `target`, `findings` and `log` fields. `target` is the last launched target. `runs` lists IDs, normalized targets, types, parent run IDs, outcomes and error counts. Findings keep their original fields and add `run_id` and `pivot`. Export during a run captures a point-in-time snapshot and can include outcome `running`.

Exports and settings stage owner-only files (mode 0600) before publishing them atomically. Export uses a new name on collision. Settings replace the previous file on success. The log reports export write errors, and stderr reports settings save errors. The HTTP cache lives in memory only.

---

## 7. Architecture

```
src/main.cpp          UI (kit::run frame), Store, job launch, settings, export
src/osint.h           Type, Finding, Settings, Job, Module, shared helper declarations
src/util.cpp          detect(), DoH, html_text(), find_emails/phones(), phone_info()
src/findings.*        display text cleanup, per-run grouping, duplicate detection and filtering
src/case.*            case storage, coverage comparison, related sources, phone summaries and reports
src/http.{h,cpp}      the only network path
src/modules/
  modules.h           per-file module lists + pure functions exposed for tests
  registry.cpp        modules() = phone, email, username, ip, dork lists in that order
  phone.cpp email.cpp username.cpp social.cpp music.cpp ip.cpp domain.cpp dork.cpp
data/dorks.json       templates + links
tests/test_core.cpp   offline tests
third_party/nlohmann  json.hpp 3.12.0 (MIT)
```
CMake targets: `mark47_core` (static lib, no UI: everything except `main.cpp`), `snitch` (app, links `kitui_app`), `test_core`.

**Threads.** Run starts one `std::jthread` per enabled module (WhatsMyName runs its own 16-thread pool inside). Each gets a `Job` holding a **copy** of the settings and a `std::stop_token`. Findings and log lines go into `Store` under one mutex; each one calls `kit::wake()` so the idle UI redraws. The frame holds the mutex while drawing. Stop calls `request_stop()`; on exit snitch stops all jobs, then joins.

**HTTP** (`http_get(url, stop, Request)`):
- protocols limited to http/https (targets end up in URLs), up to 5 redirects;
- 8 s connect / 15 s total timeout (per request: `timeout_s`), body capped at 8 MB;
- **per-host rate limit**: a minimum interval between requests to the same host (default 1 s, scrapers 4 s, SearXNG 1.5 s, DoH 0). Waiting workers release the lock and only claim a slot when it opens.
- **session cache** of HTTP 200 plain GET responses keyed by URL. Entries expire after five minutes. The cache holds up to 128 entries and 32 MiB of URLs and response bodies, evicting oldest entries first. Requests with custom headers or POST bodies bypass it, as do dorks and WhatsMyName.
- `Request::post` switches to POST, `headers` adds headers. Firefox user agent.

Status 0 means a transport failure; `Response::error` says why.

---

## 8. Writing a module

```cpp
// src/modules/username.cpp
static void example(const Job& j) {                       // runs on a worker thread
    const Response r = http_get("https://api.example.com/u/" + url_encode(j.target), j.stop);
    if (r.status == 404) { j.log("not found"); return; }  // log = Log pane, not a finding
    if (r.status != 200) throw std::runtime_error("HTTP " + std::to_string(r.status));  // -> "Example: error: ..."
    const auto d = nlohmann::json::parse(r.body);
    j.add("name", d.value("name", ""));                    // key, value[, url]
    j.add("profile", d.value("url", ""), d.value("url", ""));
    j.pivot("email", d.value("email", ""));                // gets a Pivot button
}
// add to the list at the bottom of the file:
{"Example", "What it finds (tooltip)", Username, example},
```
Rules:
- Always `url_encode` the target in URLs.
- Pass `j.stop` to `http_get`, and check `j.stop.stop_requested()` in loops.
- Throw for failures; `nlohmann::json` parse errors are caught the same way.
- A module that accepts several types uses `Phone | Email` and checks `j.type`.
- Keep parsing in a pure function and test it (`modules.h` + `tests/test_core.cpp`).

---

## 9. Testing

`ctest --test-dir build --output-on-failure` runs `tests/test_core.cpp` (offline, asserts always on): target detection, libphonenumber parsing, email/phone extraction, HTML text extraction, template filling, mail provider mapping, the WhatsMyName rule, the DuckDuckGo/Bing/SearXNG parsers (fixtures trimmed from real pages, Nov 2026, incl. Bing's `ck/a` redirect and `msockid` stripping), and the module registry.

With Python 3, CTest also registers `http`. Its loopback fixture covers cache reuse and eviction, custom headers, redirects, Retry-After, response size, timeout, cancellation and a SearXNG 429 that should yield only manual links. The test reports a skip when process permissions block loopback sockets.

Live checks are manual: run the app against known targets. Scripted screenshots work through kitui's hooks:
```sh
KITUI_SHOT=out.ppm KITUI_SHOT_FRAMES=900 KITUI_MOUSE=768,16 KITUI_CLICK=1 ./build/snitch 8.8.8.8 && magick out.ppm out.png
```
The click happens at frame 5. A tiling WM may resize the window after start, so take one plain screenshot first to find the coordinates.

---

## 10. Limitations

- **Linux only** (system libcurl/OpenSSL/libphonenumber, `inet_pton`, `xdg-open`). See TODO → Windows.
- **Direct scraping gets blocked** (DuckDuckGo 202, Mojeek 403, Google CAPTCHA). Use SearXNG or the existing manual search links. Direct providers are paused for the remainder of the run after explicit blocks.
- **Phone carrier:** optional offline prefix metadata provides original carrier assignments where available. The current carrier of a ported number requires a separate source.
- **Past addresses / owner names** come only from search snippets and the lookup links you open yourself. People-search sites aren't scraped.
- **Rate limits:** GitHub 60 req/h (commit search 10/min), ip-api 45/min, Reddit mostly blocked. Mastodon checks mastodon.social only.
- **Font coverage:** current kitui reads UTF-8. The built-in atlas covers Latin-1, Latin Extended-A and Cyrillic. Missing glyphs render as `?`. kitui also exposes runtime TTF loading.
- **Lookup-link URL formats:** FastPeopleSearch (`/{dashed}`) is unverified. TruePeopleSearch, USPhoneBook and ThatsThem were checked against archived captures, the rest against live responses or indexed URLs (2026-11-25).
- The findings list processes every row per frame. See the 2026-11-24 profiling results below.
- Respect each site's terms and the law where you operate. Only investigate targets you're authorized to.


## 11. Change log

### 2026-11-24 · Codex handoff review

- Read the prior handoff, reviewed the CMake targets, GUI entry point, transport, module registry and providers, search templates and offline tests. Updated `TODO.md` with a prioritized improvement plan and documented current export and cancellation behavior here. Changed only these two Markdown files.
- Baseline: the existing build passed CTest (1/1). A fresh out-of-tree Ninja configure and build against local kitui also passed CTest (1/1). The dork data parsed as JSON. Git history was unavailable in the supplied workspace. Review used local source and offline checks. GUI behavior and live providers remain unverified.
- The plan preserves Linux-first, kitui-only and free/keyless defaults. It prioritizes a repeatable build, per-run provenance, reliable exports and bounded transport state. The HTTP response cap is per transfer, while the current success cache can grow across an entire session. Search work focuses on actionable failures and the browser fallback. Platform and provider expansion remain in the backlog.

### 2026-11-24 · Improvement plan implementation

- **Build and tests.** Added `MARK47_BUILD_GUI=OFF` and the optional Python-backed loopback suite in `CMakeLists.txt`. Built the GUI against clean local kitui revision `1ee1cf124b842fca490253ec952cc35553ed7d60` and built the core-only configuration. The core CTest passed in both. The HTTP fixture in `tests/http_fixture.py` and `tests/test_http.cpp` reports a skip here because the sandbox denies IPv4 socket creation. Timeouts and in-flight HTTP cancellation still need execution on a host with loopback access.
- **Runs and files.** `src/main.cpp` and `src/osint.h` track run IDs, pivot parents and outcomes, export schema v2, and publish settings and exports atomically. The offscreen SDL smoke checks used scripted mouse/text events, synthetic email and username fixtures, and no live providers. Verified Run → Pivot → Run attribution, repeated exports at mode 0600, and Stop with a paused local file fixture. Editing the input after Stop preserved the last launched target in export. An injected link failure produced an error, preserved the earlier export and left no temporary file.
- **Transport and search.** `src/http.*` bounds the GET cache, skips custom-header and POST caching, defers rate-limit claims until dispatch, and exposes the presence of Retry-After. `src/modules/dork.cpp` distinguishes malformed SearXNG replies, empty responses, transport failures and provider blocks. It keeps manual links and skips blocked direct providers for that run. `tests/test_core.cpp` covers valid empty and malformed SearXNG payloads. Live providers were not exercised.
- **kitui profiling.** SDL offscreen rendering at 1280×760 and scale 1, forced redraw via `KITUI_SHOT`, synthetic local Lookup links, and monotonic timing between swap calls. The last 120 frame intervals gave median/p95 of 0.79/1.06 ms for one row and 21.83/31.04 ms for 4,000 rows. This is an offscreen baseline. Row virtualization remains in `TODO.md`. Checked default UTF-8 glyph coverage and the runtime TTF API against the same kitui revision.

### 2026-11-24 · Program rename

- Renamed the window to `mark47 snitch` and the GUI build target and executable to `mark47-snitch`. Existing settings are loaded from `~/.config/mark47/settings.json`, and exports still use the `mark47_` filename prefix.
- Rebuilt the GUI and captured an SDL offscreen frame. The core CTest passed. The HTTP fixture skipped because the sandbox blocks loopback TCP.

### 2026-11-24 · Findings layout and duplicate links

- Added `src/findings.*` and updated `src/main.cpp` to group newest runs first, then by source. Exact repeat rows, shared URLs, and identical pivots within a run are consolidated. Recognized GitHub profile tabs share a canonical account link. Distinct repository and page paths keep their own rows. Related rows retain their original labels, text, and links. JSON export keeps every emitted finding.
- Aligned row actions, hid unused action buttons, shortened text previews, and cleaned dork summaries and manual search labels in `src/modules/dork.cpp`.
- Extended `tests/test_core.cpp` for profile tabs, distinct repo paths, source precedence, separate runs, pivots, filtering, and weak hits. Core CTest passed. The HTTP fixture skipped because the sandbox blocks loopback TCP. An offscreen lookup fixture verified collapsed and expanded profile rows, a distinct repository row, and preservation of all five findings in export.


### 2026-11-24 · Public phone profile matches

- Added four public profile query groups in `data/dorks.json`. `src/modules/phone.cpp` checks supported profile URLs and uses libphonenumber to compare the full normalized number in the result title or snippet. Site lookalikes, reserved routes, posts and repository paths are excluded from profile matches.
- `src/modules/dork.cpp` emits the service, account identifier and original URL. `src/findings.cpp` and `src/main.cpp` prioritize these findings and group the source snippet under the match. Registration and ownership remain unknown from search evidence.
- Added offline fixtures for matching numbers, mismatches, scattered digits, lookalike sites and non-profile URLs in `tests/test_core.cpp`. The core test passed. The loopback HTTP test skipped because the sandbox blocks TCP. Live provider coverage remains unverified.


### 2026-11-24 · Offline carrier detection

- Added longest-prefix carrier matching to Number info in `src/modules/phone.cpp` and added `tools/import_carrier_data.py` for atomic import of Google's English prefix data. The generated table is ignored by Git and includes upstream license text.
- Verified the importer with a synthetic archive, including preservation of the prior table after an invalid archive. Core tests passed, and an offscreen GUI run displayed the expected fixture carrier. The HTTP suite skipped due to sandbox socket restrictions. The upstream archive download could not resolve GitHub in the sandbox, so production metadata still needs installation from a network-enabled terminal or a local archive.


### 2026-11-24 · Auto dorking findings

- `src/modules/dork.cpp` generates two target-specific public-search queries through the existing search backend. It filters results by explicit target mentions and emits at most 12 distinct URLs. `src/modules/phone.cpp` shares the full-number matcher with generated phone searches.
- `src/main.cpp` and `src/findings.cpp` preserve the **Auto dorking** section in Findings and JSON exports. Its hits remain visible when template searches or modules find the same URL.
- Added offline fixtures in `tests/test_core.cpp` for query generation, token/number matching, and separate grouping. The public proxy-list rotation requested for provider blocks remains outside this implementation.


### 2026-11-24 · Authorized search proxy list

- `src/modules/dork.cpp` loads a user-supplied list for direct search fallback. It keeps one proxy until a confirmed connection failure and uses manual links if every configured endpoint is unreachable. No proxy endpoints are fetched automatically.
- `src/http.*` applies explicit libcurl proxy routing and distinguishes connection failures from CONNECT denials. Host pacing is independent of proxy choice. DNS/connect failures can fail over, while providers’ HTTP responses and challenges retain the existing block behavior.
- Added list parser fixtures and loopback tests for an offline proxy and a refused CONNECT. Core tests passed. The HTTP suite skipped in this sandbox because IPv4 sockets are blocked. No live proxy was configured for this review.


### 2026-11-24 · Major OSINT roadmap

- Reviewed the existing run IDs, pivot ancestry, duplicate grouping, provider logs, public phone evidence and export format. Added five milestones and acceptance criteria to [TODO.md](TODO.md#major-osint-roadmap).
- Evidence review and reopenable cases come first. They supply exact pivot provenance and source comparison for later domain research, provider replay and phone triage. This entry records planning only.


### 2026-11-24 · Evidence review and local cases

- Added a case format in `src/case.*` with stable evidence IDs, exact pivot references, provider/query/match metadata, observation times and review notes. The parser checks evidence IDs and ancestry before opening a case. The existing schema-v2 JSON export remains available.
- Added **Details**, **Save case**, **Open case**, **Via E…** and **Report** in `src/main.cpp`. Source-linked reports include targets, findings, queries and notes. Duplicate references to the same URL share a citation. Attribution across syndicated URLs remains open.
- `src/modules/dork.cpp` records engine/query context and attaches the source URL to linked phone and email pivots. The UI keeps Copy on those pivots pointed at the target value.
- Offline core tests cover case round trips, invalid pivot references, and report citations. An offscreen GUI check exercised Run, Pivot, Save case, Clear, Open case, and Report. The edited review status and note survived the round trip. The HTTP fixture skipped because the sandbox blocks loopback TCP.


### 2026-11-24 · Next major release plan

- The roadmap now prioritizes a passive Domain target and coverage-aware comparison between case runs. It records acceptance criteria for dated pivots, missing versus unavailable evidence, and offline replay. Source comparison and phone triage follow. See [TODO.md](TODO.md#next-major-release--domain-research-and-case-comparison).


### 2026-11-24 · Domain research, comparisons, source review and phone summaries

- Added explicit Domain targets, public DNS/RDAP and bounded certificate/archive history in `src/modules/domain.cpp`. Typed pivots preserve Domain and IP intent. Email domains and valid PTR hostnames also pivot to Domain.
- Added provider coverage records for domain checks and search queries. The new comparison pane reviews two saved runs and checks coverage before calling any evidence absent. Case version 1 reads old cases and stores optional coverage and typed-pivot metadata for new ones.
- Added source origin, publication/capture dates and excerpts to evidence details, comparison and reports. Recorded shared origins and matching text are labeled separately.
- Added phone summaries with profile leads, conflicting observations and coverage gaps. Carrier imports retain dataset version, archive timestamp when present, and import date.
- Core fixtures covered DNS states, certificate boundaries, typed pivots, old/new case replay, blocked rechecks, declared source relationships and phone conflicts. An offscreen saved-case check displayed changed DNS, unknown coverage after a block, dated source provenance, and multiple phone profile leads. The carrier importer passed a synthetic version/date fixture. Live provider calls and HTTP loopback verification remain open.

### 2026-11-24 · SoundCloud, Spotify and track credits

- Added SoundCloud oEmbed username lookup, public music queries, a Spotify track target, track-link pivots and an explicit clipboard credits import. Credit findings retain role, credited text, track URL and evidence basis.
- Core fixtures cover Spotify URL and URI parsing, exact ID versus lead classification, SoundCloud embed validation, English credit roles, case serialization and separate credit rows. An offscreen GUI test imported three distinct roles and confirmed their track links in the saved case and credited names in the report. Live music-provider checks remain open. The HTTP suite skipped because the sandbox blocks loopback TCP.


### 2026-11-24 · Automatic Spotify track credits

- Spotify track URLs and URIs use **Run** directly. Removed the clipboard credits panel and its parser. Existing cases keep their saved credit evidence.
- Track runs check MusicBrainz for the exact Spotify URL first, then cross-check a unique exact public title and artist where available. Findings retain composer, songwriter, lyricist, production and other supported roles with recording/work links and match basis. An ambiguous lookup or an unavailable provider produces a status row.
- Core fixtures exercise exact URL linkage, unique and ambiguous title/artist matches, recording/work credits, and case serialization. An offscreen GUI check verified that Run auto-detects a pasted track URL and displays lookup status without a separate button. Live MusicBrainz attribution remains unverified because the sandbox blocks network requests.


### 2026-11-24 · Direct social profile leads

- Username runs now strip whitespace and a leading `@` before querying modules. The **Social profiles** module builds public profile URLs on seven sites and displays any potential accounts with the platform, normalized handle and URL. SoundCloud uses its existing oEmbed module and the same row label. WhatsMyName remains available for additional sites.
- The direct checks reject obvious error and login pages, challenge responses, and redirects to a different URL. Public HTTP responses are leads. Added offline fixtures for normalization, URL construction, platform aliases and filtered responses. An offscreen run confirmed that `@Ali ce` reaches the modules as `Alice`. Core tests passed. Live provider behavior remains unverified, and the HTTP fixture skipped because the sandbox blocks loopback TCP.


### 2026-11-24 · Expanded direct profile URLs

- Added SoundCloud, Last.fm, Letterboxd, GitLab, DEV Community, Behance, Medium and Vimeo to **Social profiles**. The module runs up to four checks in parallel and preserves the full path when validating redirects for routes such as Last.fm’s `/user/`. Vimeo is checked for alphanumeric vanity aliases containing a letter. [Letterboxd profile URLs](https://support.letterboxd.com/hc/en-us/articles/15179404766863-What-s-my-username) [Vimeo custom URLs](https://help.vimeo.com/hc/en-us/articles/12425669540113-About-managing-your-Vimeo-profile-page)
- If SoundCloud oEmbed and the direct URL both surface the same profile, Findings groups them under the direct **Potential account** row. The core fixtures cover all added URL templates, legitimate and unrelated redirects, and SoundCloud grouping. Live provider behavior remains unverified.


### 2026-11-24 · Solo.to and Carrd profile URLs

- Added `https://solo.to/<handle>` and `https://<handle>.carrd.co/` to **Social profiles**. Carrd checks require a valid single DNS label. The checker accepts the same Carrd homepage with or without a trailing slash and excludes missing-site pages and redirects to other hosts. [Solo.to profile format](https://help.solo.to/article/16-getting-your-solo-link) [Carrd hosting format](https://carrd.com/docs/sites/using-a-custom-subdomain)
- Added offline fixtures for both templates, Carrd label validation, homepage normalization and missing-site handling.


### 2026-11-24 · Cash App profile URLs

- Added the public `https://cash.app/$<handle>` route to **Social profiles** for alphanumeric handles. Username input accepts an optional leading dollar sign. The checker accepts the equivalent URL-encoded dollar sign on redirects. Matching pages appear as **Potential account**. [Public $Cashtags](https://cash.app/learn/getting-started/how-to-send-and-receive-money)
- Added offline fixtures for input normalization, URL generation, redirects and invalid Cashtag punctuation.


### 2026-11-24 · WhatsMyName roster audit

- The upstream repository was archived on November 9, 2026. The local roster snapshot has 691 entries, including one disabled entry (7cup). Mark47 attempts the other 690 when the module is enabled and the dataset loads. Individual provider rules can age independently of the archived list. [Archived upstream repository](https://github.com/WebBreacher/WhatsMyName)


### 2026-11-24 · Bundled username catalog

- Adapted the full 691-entry WhatsMyName roster in `data/username-sites.json`, preserving CC BY-SA attribution. **Social profiles** now runs the bundled catalog with the direct checks. Removed the separate remote-fetching module.
- The adapted catalog uses public GETs. It retains 656 status/marker rules and 30 public profile substitutes. Four entries have no usable public profile route and one is disabled. Provider rate limits defer later checks to the same host. Existing disabled WhatsMyName settings migrate to **Full profile catalog**.
- Core tests verified the catalog counts and status/marker behavior. Live provider checks remain unverified, and the HTTP test skipped in this sandbox.


### 2026-11-24 · External WhatsMyName fallback

- Added an independent **WhatsMyName fallback** checkbox under username Modules. Existing direct checks and the bundled catalog still run as configured. Enabled runs without local profile hits get a browser link with the normalized username. The handoff runs after the local modules finish and a Stop suppresses it.
- Core tests verified the fallback URL, run scoping and suppression after a local hit. An offscreen username run verified the checkbox and fallback row. WhatsMyName.app returned HTTP 403 to the browser verification tool, so live handoff remains unverified.


### 2026-11-24 · Default username fallback and User-Agent

- New settings enable both **Social profiles** and **WhatsMyName fallback**. Saved checkbox choices take precedence. At that point the browser fallback appeared only after a username run with no local profile hit.
- Direct and bundled profile requests now use `Mark47Snitch/1.0 (public profile lookup)`. Custom User-Agent requests bypass the shared response cache, and existing block handling applies. Added an echo fixture for the header. Live block rates remain unverified.


### 2026-11-24 · Always expose the enabled WhatsMyName web search

- An enabled WhatsMyName fallback now adds its browser link immediately on each username run, including when a local account has already been found. This avoids hiding the external search when the user wants a second source. The query is sent when the user clicks **Open**.


### 2026-11-24 · WhatsMyName hits in Findings

- Bundled roster hits and the external search link now appear under **WhatsMyName**. Direct checks still populate **Social profiles**. Shared requests can generate a lead in both sections when each check matches.
- The **Import WMN CSV** action attaches the official site's exported hits to the selected username run. It handles quoted CSV, recognizes successful status rows where present, validates supplied usernames and deduplicates reimported hits. [WhatsMyName export support](https://github.com/WebBreacher/WhatsMyName#tools-and-sites-that-use-whatsmyname)
- Core tests and an offscreen import/export check passed. Live WhatsMyName.app access remains unverified. The app uses the documented browser and CSV workflow for live service results.


### 2026-11-25 · Profile findings routing and Stripchat responses

- Direct and bundled checks now report together under **Social profiles**. Compatible overlapping checks emit one potential hit. Legacy case files using the combined WhatsMyName label display with the updated source labels.
- A Stripchat profile URL can be a potential hit when it returns a usable successful response on the expected path, including a page with a generic Stripchat title. HTTP 404, obvious missing-page titles, login redirects and blocked responses remain excluded. Unsuccessful Stripchat requests log their response status.
- WhatsMyName.app publishes a browser and CSV workflow. No supported public results API was found in the provider documentation, so the web link stays under **WhatsMyName fallback** and external CSV results under **WhatsMyName (CSV)**. [Provider’s tool listing](https://www.osintcombine.com/free-osint-tools)


### 2026-11-25 · Stripchat HTML content negotiation

- The Stripchat public profile check now sends `Accept: text/html` and retains the Mark47 Snitch User-Agent. HTTP 406 is logged explicitly and counted as unavailable.
- Added fixtures for the bundled header and transport content negotiation. Live response behavior remains unverified.


### 2026-11-25 · Search engine list and lookup-link formats

- Removed `mojeek` and `qwant` from the SearXNG engine lists in `src/modules/dork.cpp`. Through a local SearXNG, Mojeek returned HTTP 403 (proof-of-work CAPTCHA, inactive in SearXNG defaults) and Qwant returned access denied or timed out.
- Checked the phone lookup links in `data/dorks.json`. Sync.ME now uses `{digits}`. The previous `{e164_url}` produced a doubled `++` in the page's number. TruePeopleSearch now uses `{dashed}`, matching archived `resultphone?phoneno=` captures. Whitepages, 800notes, Sync.ME, `wa.me` and `t.me` were confirmed from live responses or indexed URLs. USPhoneBook and ThatsThem match archived captures. FastPeopleSearch could not be verified because the site returns a challenge page and the Internet Archive CDX service was offline. Direct requests to TruePeopleSearch, FastPeopleSearch, USPhoneBook, ThatsThem and Whitepages return bot challenges. These links are intended for the browser.


### 2026-11-25 · WhatsMyName label

- The **WhatsMyName fallback** module checkbox and Findings section are now labeled **WhatsMyName**. The saved toggle keeps its settings key, so existing choices carry over. Case files saved with the old label open under the new one. **WhatsMyName (CSV)** is unchanged.


### 2026-11-25 · Settings panel and Discord token

- A **Settings** button next to **Report** opens a panel in place of Findings, with **Back** to return. It stores an optional Discord user token in `~/.config/mark47/keys.json` (owner-only, atomic write) and keeps it out of `settings.json`. Input is trimmed and must look like a token (50–200 characters of `A–Z a–z 0–9 . _ -`). The panel shows only the last four characters after saving. kitui has no masked input, so the field shows the token while it is typed.
- No module uses the token yet. Automating a user account violates Discord's terms.
- An offscreen check confirmed the button, panel, and loading of a saved token. Save and Remove were not exercised in the GUI because kitui's test hooks cannot type text.


### 2026-11-25 · Discord username check

- Added a **Discord** username module in `src/modules/username.cpp`. It sends the saved user token in one POST to `/api/v9/users/@me/pomelo-attempt` and records **Username taken** or **Username available** with Discord coverage. It skips without a token or for invalid names. It reports 401/403, 429 (with `retry_after`), CAPTCHA and other 400 responses separately and does not retry. The token reaches jobs through `Settings`. It is re-validated before use and is never written to `settings.json`, exports, cases or reports.
- Core tests cover username normalization and rules, token validation including header injection, and module registration. A fake-token request returned HTTP 401, which confirms the endpoint path. A real-token response was not exercised. The endpoint is undocumented and can change. Automating a user account violates Discord's terms.

### 2026-11-25 · Renamed to snitch

- The program is now just `snitch`: window title, GUI build target and executable (`./build/snitch`), and the User-Agent (`snitch/1.0 (public profile lookup)`, `snitch/1.0 (local music metadata lookup)`). Internal names are unchanged: the `mark47_core` library, settings in `~/.config/mark47/settings.json`, and the `mark47_` export filename prefix.

### 2026-11-25 · Install from the terminal

- `cmake --install build --prefix ~/.local` installs `~/.local/bin/snitch` and copies `data/` to `~/.local/share/snitch`, so `snitch` runs from any directory.
- `data_path()` order: `MARK47_DATA`, then `<exe>/../share/snitch` when the file exists there, then the source `data/` compiled in. `username-sites.json` now goes through `data_path()` too, so `MARK47_DATA` covers it. Checked with a probe linked against `mark47_core`: build-tree runs read the source `data/`, the `~/.local` install reads `~/.local/share/snitch`.
