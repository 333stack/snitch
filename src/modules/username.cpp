// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include <cstring>
#include <ctime>
#include <set>
#include <stdexcept>

#include "http.h"
#include "modules.h"

using json = nlohmann::json;

static Response must(const Response& r, std::initializer_list<long> ok = {200}) {
    for (long s : ok) if (r.status == s) return r;
    throw std::runtime_error(r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
}

static void github(const Job& j) {
    const Request api{.headers = {"Accept: application/vnd.github+json"}};
    const Response r = http_get("https://api.github.com/users/" + url_encode(j.target), j.stop, api);
    if (r.status == 404) { j.log("no GitHub user"); return; }
    if (r.status == 403 || r.status == 429) throw std::runtime_error("GitHub rate limit (60 requests/hour without a token)");
    const json u = json::parse(must(r).body);
    j.add("profile", u.value("html_url", ""), u.value("html_url", ""));
    for (const char* f : {"name", "company", "blog", "location", "email", "bio", "twitter_username", "created_at"})
        if (u.contains(f) && u[f].is_string() && !u[f].get<std::string>().empty()) j.add(f, u[f].get<std::string>());
    j.add("repos / followers", std::to_string(u.value("public_repos", 0)) + " / " + std::to_string(u.value("followers", 0)));

    // Commit author emails from the most recently pushed own repos (3 repos -> 4 requests of the 60/hour budget).
    const Response rr = http_get("https://api.github.com/users/" + url_encode(j.target) + "/repos?sort=pushed&per_page=10", j.stop, api);
    if (rr.status != 200) return;
    std::set<std::string> emails;
    int checked = 0;
    for (const auto& repo : json::parse(rr.body)) {
        if (repo.value("fork", false) || checked++ == 3) continue;
        const Response c = http_get("https://api.github.com/repos/" + repo.value("full_name", "") + "/commits?per_page=30&author=" + url_encode(j.target), j.stop, api);
        if (c.status != 200) continue;
        for (const auto& cm : json::parse(c.body)) {
            const std::string e = cm["commit"]["author"].value("email", "");
            if (!e.empty() && e.find("noreply.github.com") == std::string::npos) emails.insert(e);
        }
    }
    for (auto& e : emails) j.pivot("commit email", e);
}

// "created (unix)" / "seen (ms)" fields -> "created" = 2021-09-22
static std::pair<std::string, std::string> as_date(std::string label, const json& v) {
    for (auto [suffix, div] : {std::pair{" (unix)", 1LL}, std::pair{" (ms)", 1000LL}}) {
        if (!label.ends_with(suffix) || !v.is_number()) continue;
        const time_t t = time_t(v.get<long long>() / div);
        char buf[16];
        std::strftime(buf, sizeof buf, "%Y-%m-%d", std::gmtime(&t));
        return {label.substr(0, label.size() - strlen(suffix)), buf};
    }
    return {label, v.is_string() ? v.get<std::string>() : v.dump()};
}

static void json_profile(const Job& j, const std::string& url, const std::string& page,
                         std::initializer_list<std::pair<const char*, const char*>> fields, Request req = {}) {
    const Response r = http_get(url, j.stop, req);
    if (r.status == 404 || r.status == 410) { j.log("not found"); return; }
    const json d = json::parse(must(r).body);
    if (d.is_null() || (d.is_object() && d.contains("error"))) { j.log("not found"); return; }
    j.add("profile", page, page);
    for (auto& [path, label] : fields) {
        const json v = d.value(json::json_pointer(path), json());
        if (v.is_null() || v == "" || v == json::array()) continue;
        auto [k, val] = as_date(label, v);
        j.add(k, val);
    }
}

static void hackernews(const Job& j) {
    json_profile(j, "https://hacker-news.firebaseio.com/v0/user/" + url_encode(j.target) + ".json",
                 "https://news.ycombinator.com/user?id=" + url_encode(j.target), {{"/created", "created (unix)"}, {"/karma", "karma"}, {"/about", "about"}});
}

static void lichess(const Job& j) {
    json_profile(j, "https://lichess.org/api/user/" + url_encode(j.target), "https://lichess.org/@/" + url_encode(j.target),
                 {{"/createdAt", "created (ms)"}, {"/seenAt", "last seen (ms)"}, {"/profile/realName", "real name"},
                  {"/profile/bio", "bio"}, {"/profile/location", "location"}, {"/profile/flag", "flag"}, {"/profile/links", "links"}});
}

static void chesscom(const Job& j) {
    json_profile(j, "https://api.chess.com/pub/player/" + url_encode(j.target), "https://www.chess.com/member/" + url_encode(j.target),
                 {{"/name", "name"}, {"/location", "location"}, {"/country", "country"}, {"/joined", "joined (unix)"}, {"/last_online", "last online (unix)"}});
}

static void keybase(const Job& j) {
    const json d = json::parse(must(http_get("https://keybase.io/_/api/1.0/user/lookup.json?usernames=" + url_encode(j.target), j.stop)).body);
    const json them = d.value("them", json::array());
    if (them.empty() || them[0].is_null()) { j.log("no Keybase user"); return; }
    const json& u = them[0];
    j.add("profile", "https://keybase.io/" + j.target, "https://keybase.io/" + j.target);
    if (u.contains("profile") && u["profile"].is_object())
        for (const char* f : {"full_name", "location", "bio"})
            if (u["profile"].value(f, json()).is_string()) j.add(f, u["profile"][f].get<std::string>());
    for (const auto& p : u.value(json::json_pointer("/proofs_summary/all"), json::array()))
        j.add("proof: " + p.value("proof_type", ""), p.value("nametag", ""), p.value("service_url", ""));
}

static void bluesky(const Job& j) {
    const std::string h = j.target.find('.') == std::string::npos ? j.target + ".bsky.social" : j.target;
    json_profile(j, "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=" + url_encode(h), "https://bsky.app/profile/" + h,
                 {{"/displayName", "name"}, {"/description", "bio"}, {"/createdAt", "created"}, {"/did", "DID"},
                  {"/followersCount", "followers"}, {"/postsCount", "posts"}});
}

static void mastodon(const Job& j) {
    // shortcut: only checks mastodon.social; other instances need the full @user@host handle.
    json_profile(j, "https://mastodon.social/api/v1/accounts/lookup?acct=" + url_encode(j.target), "https://mastodon.social/@" + j.target,
                 {{"/display_name", "name"}, {"/note", "bio (html)"}, {"/created_at", "created"}, {"/fields", "profile fields"}});
}

static void reddit(const Job& j) {
    const Response r = http_get("https://www.reddit.com/user/" + url_encode(j.target) + "/about.json", j.stop);
    if (r.status == 404) { j.log("no Reddit user"); return; }
    if (r.status == 403 || r.status == 429) throw std::runtime_error("Reddit blocked the request (common without OAuth)");
    const json d = json::parse(must(r).body).value("data", json::object());
    if (d.value("is_suspended", false)) { j.add("status", "suspended"); return; }
    j.add("profile", "https://www.reddit.com/user/" + j.target, "https://www.reddit.com/user/" + j.target);
    j.add("created", as_date("created (unix)", (long long)d.value("created_utc", 0.0)).second);
    j.add("karma", std::to_string(d.value("total_karma", 0)));
    if (d.contains("subreddit") && d["subreddit"].is_object() && !d["subreddit"].value("public_description", "").empty())
        j.add("bio", d["subreddit"].value("public_description", ""));
}

static void wayback(const Job& j) {
    const std::string u = url_encode(j.target);
    for (const std::string& site : {"twitter.com/" + u, "x.com/" + u, "instagram.com/" + u, "facebook.com/" + u, "tiktok.com/@" + u,
                                   "youtube.com/@" + u, "github.com/" + u, "reddit.com/user/" + u}) {
        if (j.stop.stop_requested()) return;
        const Response r = http_get("https://web.archive.org/cdx/search/cdx?output=json&fl=timestamp,original,statuscode&filter=statuscode:200&collapse=timestamp:6&url=" + url_encode(site), j.stop, {.timeout_s = 30});
        if (r.status != 200) { j.log(site + ": " + (r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error)); continue; }
        const json rows = json::parse(r.body.empty() ? "[]" : r.body);
        if (rows.size() < 2) continue;  // first row is the header
        const std::string first = rows[1][0], last = rows.back()[0];
        j.add("archived " + site.substr(0, site.find('/')), std::to_string(rows.size() - 1) + " snapshots " + first.substr(0, 8) + " .. " + last.substr(0, 8),
              "https://web.archive.org/web/" + first + "/" + rows[1][1].get<std::string>());
    }
}

std::string discord_username(std::string_view input) {
    auto name = normalize_username(input);
    for (auto& ch : name) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    if (name.size() < 2 || name.size() > 32 || name.find("..") != name.npos ||
        name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_.") != name.npos) return {};
    return name;
}

// Discord tokens are base64url segments joined by dots; anything else could break the header.
bool plausible_discord_token(std::string_view token) {
    return token.size() >= 50 && token.size() <= 200 &&
           token.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-") == token.npos;
}

// Undocumented endpoint behind Discord's change-username field; one request per run, no retries.
static void discord(const Job& j) {
    const auto report = [&](CoverageState state) {
        if (j.coverage) j.coverage({"Discord", "Username registration", state});
    };
    if (j.settings.discord_token.empty()) { j.log("no token saved (top bar → Settings), skipped"); report(CoverageState::Skipped); return; }
    if (!plausible_discord_token(j.settings.discord_token)) throw std::runtime_error("saved token is malformed; save it again in Settings");
    const auto name = discord_username(j.target);
    if (name.empty()) { j.log("not a valid Discord username (2-32 of a-z 0-9 _ .), skipped"); report(CoverageState::Skipped); return; }
    const Response r = http_get("https://discord.com/api/v9/users/@me/pomelo-attempt", j.stop,
        {.headers = {"Authorization: " + j.settings.discord_token, "Content-Type: application/json"},
         .post = json{{"username", name}}.dump()});
    if (j.stop.stop_requested()) return;
    const json d = json::parse(r.body, nullptr, false);
    if (r.status == 401 || r.status == 403) { report(CoverageState::Blocked); throw std::runtime_error("Discord rejected the saved token (HTTP " + std::to_string(r.status) + ")"); }
    if (r.status == 429) {
        report(CoverageState::Blocked);
        const auto wait = d.is_object() && d.contains("retry_after") && d["retry_after"].is_number() ? d["retry_after"].dump() + " s" : "unknown";
        throw std::runtime_error("Discord rate limit, retry after " + wait);
    }
    if (r.status == 400 && d.is_object() && d.contains("captcha_key")) { report(CoverageState::Blocked); throw std::runtime_error("Discord asked for a CAPTCHA"); }
    if (r.status == 400) { j.log("Discord rejected the username: " + (d.is_object() ? d.value("message", r.body) : r.body)); report(CoverageState::Unavailable); return; }
    if (r.status != 200 || !d.is_object() || !d.contains("taken") || !d["taken"].is_boolean()) {
        report(CoverageState::Unavailable);
        throw std::runtime_error(r.error.empty() ? "unexpected response (HTTP " + std::to_string(r.status) + ")" : r.error);
    }
    const bool taken = d["taken"].get<bool>();
    j.add(taken ? "Username taken" : "Username available", name, "",
          {.provider = "Discord", .query = name, .basis = "Authenticated username availability check", .scope = "Discord username"});
    report(taken ? CoverageState::Complete : CoverageState::Empty);
}

const std::vector<Module>& username_modules() {
    static const std::vector<Module> m = {
        {"GitHub", "Profile + commit emails from recent repos (60 req/hour)", Username, github},
        {"Reddit", "Account age, karma, bio (often blocked without OAuth)", Username, reddit},
        {"Hacker News", "Account age, karma, about", Username, hackernews},
        {"Lichess", "Profile, real name, location, links", Username, lichess},
        {"Chess.com", "Profile, name, location, join date", Username, chesscom},
        {"Keybase", "Identity proofs linking other accounts", Username, keybase},
        {"Bluesky", "<name>.bsky.social profile", Username, bluesky},
        {"Mastodon", "mastodon.social profile", Username, mastodon},
        {"Discord", "Is the username taken? Uses the token saved in Settings; automating a user account breaks Discord's terms", Username, discord},
        {"Wayback", "Archived profile pages (incl. deleted accounts) on big platforms", Username, wayback},
    };
    return m;
}
