// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <regex>
#include <map>
#include <set>
#include <stdexcept>

#include "http.h"
#include "modules.h"

using json = nlohmann::json;
using Vars = std::vector<std::pair<std::string, std::string>>;

std::string fill(std::string t, const Vars& vars) {
    for (auto& [k, v] : vars)
        for (size_t p = t.find("{" + k + "}"); p != std::string::npos; p = t.find("{" + k + "}", p + v.size())) t.replace(p, k.size() + 2, v);
    return t;
}

static std::string url_decode(std::string_view s) {
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size() && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2])) {
            out += char(std::stoi(std::string(s.substr(i + 1, 2)), nullptr, 16));
            i += 2;
        } else out += s[i] == '+' ? ' ' : s[i];
    }
    return out;
}

static std::string b64url_decode(std::string_view s) {
    std::string out;
    int val = 0, bits = -8;
    for (char ch : s) {
        const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        const char* p = strchr(tbl, ch == '+' ? '-' : ch == '/' ? '_' : ch);
        if (!p || !ch) break;
        val = (val << 6) + int(p - tbl);
        if ((bits += 6) >= 0) { out += char((val >> bits) & 0xff); bits -= 8; }
    }
    return out;
}

static std::string amp(std::string s) {  // &amp; in attribute values
    for (size_t p = s.find("&amp;"); p != std::string::npos; p = s.find("&amp;", p + 1)) s.erase(p + 1, 4);
    return s;
}

static std::string attr(std::string_view tag, std::string_view name) {
    const std::string key = std::string(name) + "=\"";
    const size_t b = tag.find(key);
    if (b == std::string_view::npos) return "";
    const size_t e = tag.find('"', b + key.size());
    return amp(std::string(tag.substr(b + key.size(), e - b - key.size())));
}

// Inner HTML of the element whose opening tag contains `pos`, up to `close`.
static std::string inner(std::string_view h, size_t pos, std::string_view close) {
    const size_t b = h.find('>', pos);
    if (b == std::string_view::npos) return "";
    const size_t e = h.find(close, b);
    return std::string(h.substr(b + 1, (e == std::string_view::npos ? h.size() : e) - b - 1));
}

std::vector<SearchResult> parse_searxng(const std::string& body, std::vector<std::string>* failed) {
    const json d = json::parse(body);
    std::vector<SearchResult> out;
    const auto& results = d.at("results");
    if (!results.is_array()) throw std::runtime_error("SearXNG results must be an array");
    for (const auto& r : results) {
        SearchResult s{r.value("url", ""), r.value("title", ""), r.value("content", ""), {}};
        for (const auto& e : r.value("engines", json::array())) s.engines.push_back(e);
        if (auto it = r.find("canonical_url"); it != r.end() && it->is_string()) s.source_origin = it->get<std::string>();
        if (auto it = r.find("publishedDate"); it != r.end() && it->is_string()) s.source_date = it->get<std::string>();
        if (!s.url.empty()) out.push_back(std::move(s));
    }
    if (failed)
        for (const auto& u : d.value("unresponsive_engines", json::array()))
            failed->push_back(u.size() > 1 ? u[0].get<std::string>() + " (" + u[1].get<std::string>() + ")" : u.dump());
    return out;
}

// shortcut: string-matching scrapers for the current DDG/Bing markup; when they return nothing, check the markup first.
std::vector<SearchResult> parse_ddg(const std::string& h) {
    std::vector<SearchResult> out;
    for (size_t p = h.find("class=\"result__a\""); p != std::string::npos; p = h.find("class=\"result__a\"", p + 1)) {
        const size_t tag_b = h.rfind('<', p), tag_e = h.find('>', p);
        const std::string href = attr(std::string_view(h).substr(tag_b, tag_e - tag_b), "href");
        const size_t u = href.find("uddg=");
        if (u == std::string::npos) continue;  // ads go through y.js
        SearchResult r{url_decode(href.substr(u + 5, href.find('&', u) - u - 5)), html_text(inner(h, p, "</a>")), "", {"duckduckgo"}};
        const size_t next = h.find("class=\"result__a\"", p + 1), sn = h.find("class=\"result__snippet\"", p);
        if (sn != std::string::npos && sn < next) r.snippet = html_text(inner(h, sn, "</a>"));
        out.push_back(std::move(r));
    }
    return out;
}

std::vector<SearchResult> parse_bing(const std::string& h) {
    std::vector<SearchResult> out;
    const std::string mark = "<li class=\"b_algo\"";
    for (size_t p = h.find(mark); p != std::string::npos;) {
        const size_t next = h.find(mark, p + 1);
        const std::string blk = h.substr(p, next == std::string::npos ? std::string::npos : next - p);
        p = next;
        const size_t h2 = blk.find("<h2"), a = h2 == std::string::npos ? h2 : blk.find("<a ", h2);
        if (a == std::string::npos) continue;
        std::string url = attr(blk.substr(a, blk.find('>', a) - a), "href");
        if (const size_t u = url.find("&u=a1"); url.find("bing.com/ck/a") != std::string::npos && u != std::string::npos)
            url = b64url_decode(url.substr(u + 5, url.find('&', u + 1) - u - 5));  // click-tracking redirect
        if (const size_t m = url.find("msockid="); m != std::string::npos && m > 0 && (url[m - 1] == '?' || url[m - 1] == '&')) {
            const size_t e = url.find('&', m);  // per-request tracking id would defeat de-duplication
            url.erase(e == std::string::npos ? m - 1 : m, e == std::string::npos ? std::string::npos : e - m + 1);
        }
        const size_t para = blk.find("<p", a);
        out.push_back({url, html_text(inner(blk, a, "</a>")), para == std::string::npos ? "" : html_text(inner(blk, para, "</p>")), {"bing"}});
    }
    return out;
}

static std::string fail_text(const Response& r) {
    return r.status || r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error;
}

static std::string lower(std::string s);

static bool provider_blocked(const Response& r) {
    return r.status == 202 || r.status == 403 || r.status == 429 || r.retry_after;
}

std::vector<std::string> read_search_proxies(std::istream& config) {
    static const std::regex endpoint(R"((https?|socks5h)://([A-Za-z0-9.-]+|\[[A-Fa-f0-9:.]+\]):([0-9]{1,5})/?)");
    std::vector<std::string> proxies;
    size_t line_number = 0;
    for (std::string line; std::getline(config, line);) {
        ++line_number;
        const auto first = line.find_first_not_of(" \t\r");
        if (first == line.npos || line[first] == '#') continue;
        line = line.substr(first, line.find_last_not_of(" \t\r") - first + 1);
        std::smatch match;
        const auto invalid = [&] {
            return std::runtime_error("invalid search proxy at line " + std::to_string(line_number));
        };
        if (line.size() > 300 || !std::regex_match(line, match, endpoint)) throw invalid();
        const auto port = std::stoi(match[3].str());
        if (port == 0 || port > 65535) throw invalid();
        if (line.ends_with('/')) line.pop_back();
        if (std::ranges::find(proxies, line) != proxies.end()) continue;
        if (proxies.size() == 8) throw std::runtime_error("search proxy list exceeds 8 endpoints");
        proxies.push_back(std::move(line));
    }
    if (config.bad() || (config.fail() && !config.eof())) throw std::runtime_error("unable to read search proxy list");
    if (proxies.empty()) throw std::runtime_error("search proxy list is empty");
    return proxies;
}

struct Searcher {
    const Job& j;
    bool searx_ok = true;
    bool allow_direct = true;
    bool ddg_ok = true;
    bool bing_ok = true;
    std::vector<std::string> proxies;
    size_t active_proxy = 0;

    explicit Searcher(const Job& job) : j(job) {
        try {
            const auto path = data_path("search-proxies.txt");
            if (!std::filesystem::exists(path)) return;
            std::ifstream config(path);
            if (!config) throw std::runtime_error("unable to open search-proxies.txt");
            proxies = read_search_proxies(config);
        } catch (const std::exception& e) {
            allow_direct = false;
            j.log(std::string(e.what()) + "; using manual links if SearXNG is unavailable");
        }
    }

    Response get_direct_engine(const std::string& url) {
        Request req{.min_interval_s = 4, .cache = false};
        if (proxies.empty()) return http_get(url, j.stop, req);
        while (active_proxy < proxies.size() && !j.stop.stop_requested()) {
            req.proxy = proxies[active_proxy];
            auto result = http_get(url, j.stop, req);
            if (!result.proxy_unreachable || j.stop.stop_requested()) return result;
            j.log("Search proxy " + std::to_string(++active_proxy) + " unreachable");
        }
        if (!j.stop.stop_requested()) {
            allow_direct = false;
            j.log("No reachable configured search proxy; using manual links for the rest of this run");
        }
        Response result;
        result.error = j.stop.stop_requested() ? "stopped" : "configured proxies unavailable";
        return result;
    }

    void record(std::string provider, std::string scope, CoverageState state) const {
        if (j.coverage && !j.stop.stop_requested()) j.coverage({std::move(provider), std::move(scope), state});
    }

    void scrape(const char* provider, const std::string& url, const std::string& query, bool& enabled,
                std::vector<SearchResult> (*parse)(const std::string&),
                std::vector<SearchResult>& out) {
        if (!allow_direct || !enabled || j.stop.stop_requested()) {
            record(provider, query, CoverageState::Skipped);
            return;
        }
        const Response r = get_direct_engine(url);
        if (j.stop.stop_requested()) return;
        auto results = r.status == 200 ? parse(r.body) : std::vector<SearchResult>{};
        const std::string markup = results.empty() && r.status == 200 ? lower(r.body) : "";
        const bool challenge = markup.find("anomaly-modal") != std::string::npos ||
                               markup.find("captcha-form") != std::string::npos ||
                               markup.find("b_captcha") != std::string::npos ||
                               markup.find("g-recaptcha") != std::string::npos;
        if (r.status == 407 && !proxies.empty()) {
            record(provider, query, CoverageState::Blocked);
            allow_direct = false;
            j.log("Configured search proxy requires authentication; using manual links for the rest of this run");
        } else if (provider_blocked(r) || challenge) {
            record(provider, query, CoverageState::Blocked);
            enabled = false;
            j.log(std::string(provider) + " blocked or rate limited (" +
                  (challenge ? "challenge page" : fail_text(r)) + "); skipped for the rest of this run");
        } else if (r.status != 200) {
            record(provider, query, CoverageState::Unavailable);
            j.log(std::string(provider) + " failed: " + fail_text(r));
        } else if (results.empty()) {
            record(provider, query, CoverageState::Empty);
            j.log(std::string(provider) + ": no parseable results");
        } else {
            record(provider, query, CoverageState::Complete);
        }
        for (auto& result : results) out.push_back(std::move(result));
    }

    std::vector<SearchResult> run(const std::string& q) {
        if (searx_ok) {
            const char* engines = j.settings.all_engines
                ? "duckduckgo,brave,startpage,google,bing,yahoo,yandex,presearch,baidu"
                : "duckduckgo,brave,startpage";
            const Response r = http_get(j.settings.searxng + "/search?format=json&q=" + url_encode(q) + "&engines=" + engines, j.stop,
                                        {.timeout_s = 30, .min_interval_s = 1.5, .cache = false});
            if (j.stop.stop_requested()) return {};
            std::string failure = fail_text(r);
            if (r.status == 200) {
                try {
                    std::vector<std::string> failed;
                    auto results = parse_searxng(r.body, &failed);
                    for (const auto& f : failed) {
                        j.log("engine failed: " + f);
                        const auto reason = lower(f);
                        record("SearXNG/" + f.substr(0, f.find(" (")), q,
                               reason.find("captcha") != reason.npos || reason.find("429") != reason.npos ||
                               reason.find("403") != reason.npos ? CoverageState::Blocked : CoverageState::Unavailable);
                    }
                    record("SearXNG", q, results.empty() ? (failed.empty() ? CoverageState::Empty : CoverageState::Unavailable)
                                                          : CoverageState::Complete);
                    record("DuckDuckGo fallback", q, CoverageState::Skipped);
                    record("Bing fallback", q, CoverageState::Skipped);
                    if (results.empty()) j.log(failed.empty() ? "SearXNG: no results" : "SearXNG: no results; some engines failed");
                    return results;
                } catch (const std::exception&) {
                    failure = "malformed JSON response";
                }
            }
            record("SearXNG", q, provider_blocked(r) ? CoverageState::Blocked : CoverageState::Unavailable);
            searx_ok = false;
            if (r.status == 403) failure += "; check search.formats and access settings";
            if (r.status == 429 || r.retry_after || (!proxies.empty() && provider_blocked(r)))
                allow_direct = false;
            j.log("SearXNG unavailable (" + failure + "); " +
                  (allow_direct ? (proxies.empty() ? "using direct fallback" : "using configured proxy for search fallback")
                                : "using manual links for the rest of this run"));
        }
        else record("SearXNG", q, CoverageState::Skipped);
        std::vector<SearchResult> out;
        const auto encoded = url_encode(q);
        scrape("DuckDuckGo fallback", "https://html.duckduckgo.com/html/?q=" + encoded, q, ddg_ok, parse_ddg, out);
        if (j.settings.all_engines)
            scrape("Bing fallback", "https://www.bing.com/search?q=" + encoded, q, bing_ok, parse_bing, out);
        else record("Bing fallback", q, CoverageState::Skipped);
        return out;
    }
};

static std::string digits_of(std::string_view s) {
    std::string d;
    for (char ch : s) if (isdigit((unsigned char)ch)) d += ch;
    return d;
}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(tolower(c)); });
    return s;
}

static Vars vars_for(const Job& j, PhoneInfo* phone) {
    Vars v = {{"target", j.target}, {"target_url", url_encode(j.target)}};
    if (j.type == Email) {
        v.push_back({"local", j.target.substr(0, j.target.find('@'))});
        v.push_back({"domain", j.target.substr(j.target.find('@') + 1)});
    }
    if (j.type == Phone) {
        *phone = phone_info(j.target, j.settings.region);
        if (!phone->ok) throw std::runtime_error("not a parseable phone number");
        const std::string nat = digits_of(phone->national);
        std::string dashed = nat.size() == 10 ? nat.substr(0, 3) + "-" + nat.substr(3, 3) + "-" + nat.substr(6) : phone->national;
        std::replace(dashed.begin(), dashed.end(), ' ', '-');
        std::erase_if(dashed, [](char c) { return c == '(' || c == ')'; });
        v.insert(v.end(), {{"e164", phone->e164}, {"intl", phone->international}, {"national", phone->national}, {"dashed", dashed},
                           {"nat_digits", nat}, {"digits", phone->digits}, {"region", phone->region},
                           {"national_url", url_encode(phone->national)}, {"e164_url", url_encode(phone->e164)}});
    }
    return v;
}

std::vector<GeneratedSearch> auto_dork_queries(Type type, std::string_view target, const PhoneInfo& phone) {
    if (type != Phone && (target.empty() || target.size() > 254 ||
        std::ranges::any_of(target, [](unsigned char ch) {
            return ch <= 32 || ch == 127 || ch == '"' || ch == '\\';
        }))) return {};
    const std::string exact = '"' + std::string(target) + '"';
    switch (type) {
        case Phone:
            if (!phone.valid) return {};
            return {
                {"Contact page", '"' + phone.e164 + R"(" (contact OR "call us"))"},
                {"Public listing", '"' + phone.international + R"(" (directory OR business OR listing))"},
            };
        case Email:
            if (detect(target) != Email) return {};
            return {
                {"Public contact", exact + " (contact OR directory OR author)"},
                {"Public profile", exact + R"( (profile OR portfolio OR "about me"))"},
            };
        case Username:
            if (target.size() > 64 || !std::ranges::all_of(target, [](unsigned char ch) {
                return std::isalnum(ch) || ch == '.' || ch == '_' || ch == '-';
            })) return {};
            return {
                {"Public profile", exact + R"( (profile OR portfolio OR "about me"))"},
                {"Community profile", exact + " (member OR contributor OR community)"},
            };
        case Ip:
            if (detect(target) != Ip) return {};
            return {
                {"Network attribution", exact + " (ASN OR netblock OR operator)"},
                {"Routing reference", exact + " (routing OR allocation OR registry)"},
            };
        default: return {};
    }
}

bool auto_dork_hit(Type type, std::string_view target, const PhoneInfo& phone, const SearchResult& result) {
    if (!(result.url.starts_with("https://") || result.url.starts_with("http://"))) return false;
    if (type == Phone) return text_matches_phone(result.title, phone) || text_matches_phone(result.snippet, phone);
    if (target.empty()) return false;
    const std::string needle = lower(std::string(target));
    const auto token_char = [type](unsigned char ch) {
        return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.' ||
               (type == Ip && ch == ':') || (type == Email && (ch == '@' || ch == '+'));
    };
    auto mentions_target = [&](const std::string& value) {
        const auto haystack = lower(value);
        for (auto pos = haystack.find(needle); pos != haystack.npos; pos = haystack.find(needle, pos + 1)) {
            const auto end = pos + needle.size();
            const bool trailing_period = end < haystack.size() && haystack[end] == '.' &&
                                         (end + 1 == haystack.size() || !token_char(haystack[end + 1]));
            if ((pos == 0 || !token_char(haystack[pos - 1])) &&
                (end == haystack.size() || !token_char(haystack[end]) || trailing_period)) return true;
        }
        return false;
    };
    return mentions_target(result.title) || mentions_target(result.snippet);
}

static std::string search_excerpt(const SearchResult& result) {
    auto text = result.title;
    if (!result.snippet.empty() && result.snippet != result.title)
        text += (text.empty() ? "" : " · ") + result.snippet;
    return text;
}

static Evidence search_evidence(const SearchResult& result, const std::string& query, std::string basis) {
    std::string providers;
    for (const auto& engine : result.engines) providers += (providers.empty() ? "" : ", ") + engine;
    return {.provider = std::move(providers), .query = query, .basis = std::move(basis), .scope = query,
            .source_origin = result.source_origin, .source_date = result.source_date, .excerpt = search_excerpt(result)};
}

static std::string search_summary(const SearchResult& r) {
    std::string summary = search_excerpt(r);
    std::string engines;
    for (const auto& engine : r.engines) engines += (engines.empty() ? "" : ", ") + engine;
    if (!engines.empty()) summary += (summary.empty() ? "" : " ") + std::string("[") + engines + "]";
    return summary.empty() ? r.url : summary;
}

static void run_generated_searches(const Job& j, const PhoneInfo& phone, Searcher& searcher) {
    constexpr size_t max_hits = 12;
    std::set<std::string> seen;
    for (const auto& [label, query] : auto_dork_queries(j.type, j.target, phone)) {
        if (j.stop.stop_requested()) return;
        for (const auto& result : searcher.run(query)) {
            if (j.stop.stop_requested()) return;
            if (!auto_dork_hit(j.type, j.target, phone, result) || !seen.insert(result.url).second) continue;
            j.emit({auto_dork_section, "Potential hit · " + label, search_summary(result), result.url, false, 0,
                    search_evidence(result, query, j.type == Phone ? "Full normalized phone match" : "Exact target mention")});
            if (seen.size() == max_hits) return;
        }
    }
}

static void dorks(const Job& j) {
    const json d = json::parse(read_file(data_path("dorks.json")));
    PhoneInfo phone;
    const Vars vars = vars_for(j, &phone);
    const std::string nat = j.type == Phone ? digits_of(phone.national) : "";
    const std::string tgt = lower(j.target), local = tgt.substr(0, tgt.find('@')), domain = tgt.substr(tgt.find('@') + 1);
    auto relevant = [&](const std::string& text) {  // engines happily ignore quotes; keep only results that mention the target
        if (j.type == Phone) return digits_of(text).find(nat) != std::string::npos;
        const std::string t = lower(text);
        if (j.type == Email) return t.find(tgt) != std::string::npos || (t.find(local) != std::string::npos && t.find(domain) != std::string::npos);
        return t.find(tgt) != std::string::npos;
    };

    Searcher s{j};
    run_generated_searches(j, phone, s);
    std::set<std::string> urls, spotify_hits, profile_evidence, entities{lower(j.target), phone.e164};
    for (const auto& t : d.value(type_name(j.type), json::array())) {
        if (j.stop.stop_requested()) return;
        const std::string label = t.value("label", ""), q = fill(t.value("q", ""), vars);
        int fresh = 0;
        const auto results = s.run(q);
        if (j.stop.stop_requested()) return;
        for (const auto& r : results) {
            if (j.type == Username && !spotify_hits.contains(r.url)) {
                const auto kind = spotify_username_result(r, j.target);
                if (!kind.empty()) {
                    spotify_hits.insert(r.url);
                    const bool track = kind == "Spotify track lead";
                    j.emit({"Spotify", kind, track ? spotify_track_url(r.url) : search_summary(r), r.url,
                            track, 0, search_evidence(r, q, "Public search-index lead"),
                            track ? SpotifyTrack : Type(0)});
                    ++fresh;
                }
            }
            bool matched_profile = false;
            if (j.type == Phone && !profile_evidence.contains(r.url)) {
                const auto profile = public_phone_profile(r, phone);
                if (!profile.service.empty()) {
                    matched_profile = true;
                    profile_evidence.insert(r.url);
                    const auto evidence = search_evidence(r, q, "Full normalized phone match on an indexed profile");
                    j.add("Public match · " + profile.service, profile.handle, r.url, evidence);
                    if (detect(profile.handle) == Username && r.url.find("/channel/") == std::string::npos)
                        j.pivot("Profile handle · " + profile.service, profile.handle, r.url, evidence);
                }
            }
            if (!urls.insert(r.url).second && !matched_profile) continue;
            const std::string text = r.title + " " + r.snippet;
            const bool rel = matched_profile || relevant(text);
            const bool exact = matched_profile || auto_dork_hit(j.type, j.target, phone, r);
            const auto evidence = search_evidence(r, q, exact ? "Exact target mention" :
                                                   rel ? "Contextual target match" : "Weak search lead");
            j.add((rel ? "" : "weak ") + label, search_summary(r), r.url, evidence);
            if (!rel) continue;
            fresh++;
            for (auto& e : find_emails(text))
                if (entities.insert(e).second) j.pivot("linked email (" + label + ")", e, r.url, evidence);
            for (auto& p : find_phones(text)) {
                const PhoneInfo pi = phone_info(p, phone.ok ? phone.region : j.settings.region);
                if (pi.valid && entities.insert(pi.e164).second) j.pivot("linked phone (" + label + ")", pi.e164, r.url, evidence);
            }
        }
        if (!fresh) j.add(label + " · manual search", q, "https://www.google.com/search?q=" + url_encode(q),
                          {.provider = "Google", .query = q, .basis = "Navigation link"});
    }
}

static void links(const Job& j) {
    const json d = json::parse(read_file(data_path("dorks.json")));
    PhoneInfo phone;
    const Vars vars = vars_for(j, &phone);
    for (const auto& l : d["links"].value(type_name(j.type), json::array())) {
        if (j.stop.stop_requested()) return;
        if (l.contains("region") && phone.ok && l["region"] != phone.region) continue;
        const std::string url = fill(l.value("url", ""), vars);
        j.add("open: " + l.value("label", ""), url, url);
    }
}

const std::vector<Module>& dork_modules() {
    static const std::vector<Module> m = {
        {"Dorks", "Generated public searches and templates from data/dorks.json", Phone | Email | Ip | Username, dorks},
        {"Lookup links", "People-search / reputation pages to open in your browser (not fetched)", Phone | Email | Ip | Username, links},
    };
    return m;
}
