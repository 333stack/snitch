// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include "modules.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

#include "http.h"

namespace {
struct Site { const char* name; const char* prefix; };
constexpr Site sites[] = {
    {"X", "https://x.com/"},
    {"Instagram", "https://instagram.com/"},
    {"Facebook", "https://facebook.com/"},
    {"TikTok", "https://www.tiktok.com/@"},
    {"Twitch", "https://www.twitch.tv/"},
    {"Pinterest", "https://www.pinterest.com/"},
    {"YouTube", "https://www.youtube.com/@"},
    {"SoundCloud", "https://soundcloud.com/"},
    {"Last.fm", "https://www.last.fm/user/"},
    {"Letterboxd", "https://letterboxd.com/"},
    {"GitLab", "https://gitlab.com/"},
    {"DEV Community", "https://dev.to/"},
    {"Behance", "https://www.behance.net/"},
    {"Medium", "https://medium.com/@"},
    {"Vimeo", "https://vimeo.com/"},
    {"Solo.to", "https://solo.to/"},
    {"Cash App", "https://cash.app/$"},
};

std::string lowercase(std::string_view text) {
    std::string result(text);
    for (auto& ch : result) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    return result;
}

std::string profile_key(std::string_view url) {
    if (!url.starts_with("https://")) return {};
    url.remove_prefix(8);
    const auto boundary = url.find_first_of("/?#");
    auto host = lowercase(url.substr(0, boundary));
    if (host.starts_with("www.")) host.erase(0, 4);
    if (host.empty()) return {};
    if (host == "twitter.com") host = "x.com";
    if (host == "m.facebook.com") host = "facebook.com";
    auto path = boundary != url.npos && url[boundary] == '/' ?
        url.substr(boundary + 1, url.find_first_of("?#", boundary) - boundary - 1) : std::string_view{};
    if (path.ends_with('/')) path.remove_suffix(1);
    if (host == "cash.app" && path.starts_with("%24")) return host + "/$" + lowercase(path.substr(3));
    return host + "/" + lowercase(path);
}

bool reserved(std::string_view handle) {
    constexpr std::array<std::string_view, 17> routes{
        "about", "account", "accounts", "explore", "feed", "help", "home", "i", "login",
        "logout", "messages", "privacy", "search", "settings", "signup", "terms", "watch"
    };
    return std::ranges::find(routes, handle) != routes.end();
}

bool public_http_url(std::string_view url) {
    const auto scheme = url.starts_with("https://") ? 8U : url.starts_with("http://") ? 7U : 0U;
    if (!scheme || url.find_first_of(" \t\r\n\\") != url.npos) return false;
    const auto host = url.substr(scheme, url.find_first_of("/?#", scheme) - scheme);
    return !host.empty() && host.find('@') == host.npos;
}

std::string render_handle(std::string url, const std::string& handle) {
    constexpr std::string_view token = "{account}";
    const auto encoded = url_encode(handle);
    for (std::size_t pos = url.find(token); pos != url.npos; pos = url.find(token, pos + encoded.size()))
        url.replace(pos, token.size(), encoded);
    return url;
}

bool needs_redirect_status(long status) {
    return status >= 300 && status < 400;
}

struct ProfileCheck {
    SocialProfile profile;
    std::string request_url;
    long expected_status = 0;  // zero selects the public profile page heuristic
    std::string marker;
    std::vector<std::string> headers;
    bool direct = false;
    bool shared_catalog_rule = false;
};

void social_profiles(const Job& j) {
    const auto handle = normalize_username(j.target);
    if (handle.empty()) return;
    std::vector<ProfileCheck> checks;
    std::map<std::string, std::size_t> direct_by_url;
    for (const auto& profile : social_profile_urls(handle)) {
        direct_by_url.try_emplace(profile_key(profile.url), checks.size());
        checks.push_back({profile, profile.url, 0, "", {}, true});
    }
    std::size_t skipped = 0;
    if (j.settings.full_profile_catalog) {
        try {
            for (const auto& entry : bundled_username_catalog().at("sites")) {
                const auto mode = entry.value("mode", "");
                if (mode != "marker" && mode != "profile") { ++skipped; continue; }
                auto site_handle = handle;
                for (char ch : entry.value("strip_bad_char", "")) std::erase(site_handle, ch);
                if (site_handle.empty()) { ++skipped; continue; }
                const auto checker = entry.at("uri_check").get<std::string>();
                if (checker.find("{account}") == checker.npos) { ++skipped; continue; }
                auto request = render_handle(checker, site_handle);
                if (!public_http_url(request)) { ++skipped; continue; }
                auto link = render_handle(entry.value("uri_pretty", checker), site_handle);
                if (!public_http_url(link)) link = request;
                const auto expected = mode == "marker" ? entry.at("e_code").get<long>() : 0L;
                const auto marker = mode == "marker" ? entry.at("e_string").get<std::string>() : "";
                std::vector<std::string> headers;
                const auto declared = entry.value("headers", nlohmann::json::object());
                for (const auto& [name, value] : declared.items())
                    if (lowercase(name) == "accept" || lowercase(name) == "accept-language")
                        headers.push_back(name + ": " + value.get<std::string>());

                // Reuse a direct request when its public URL and catalog check are equivalent.
                const auto existing = direct_by_url.find(profile_key(request));
                if (existing != direct_by_url.end() && headers.empty() && !needs_redirect_status(expected) &&
                    request.find_first_of("?#") == request.npos) {
                    auto& check = checks[existing->second];
                    if (!check.shared_catalog_rule) {
                        check.expected_status = expected;
                        check.marker = marker;
                        check.shared_catalog_rule = true;
                        continue;
                    }
                }
                checks.push_back({{entry.at("name").get<std::string>(), std::move(link)}, std::move(request),
                                  expected, marker, std::move(headers), false});
            }
        } catch (const std::exception& e) {
            j.log(std::string("Bundled profile catalog: ") + e.what());
        }
    }

    std::atomic<std::size_t> next{0}, attempted{0}, found{0}, blocked{0}, unavailable{0}, throttled{0};
    std::mutex limits_mutex;
    std::set<std::string> limited_hosts;
    auto worker = [&] {
        for (std::size_t i; !j.stop.stop_requested() && (i = next++) < checks.size();) {
            const auto& check = checks[i];
            const auto& profile = check.profile;
            const auto authority = check.request_url.find("://") + 3;
            const auto host = lowercase(std::string_view(check.request_url).substr(authority,
                check.request_url.find_first_of("/?#", authority) - authority));
            {
                std::lock_guard lock(limits_mutex);
                if (limited_hosts.contains(host)) { ++throttled; continue; }
            }
            const auto response = http_get(check.request_url, j.stop, {.headers = check.headers,
                .timeout_s = check.direct ? 8 : 10, .cache = false,
                .follow_redirects = !needs_redirect_status(check.expected_status),
                .user_agent = "snitch/1.0 (public profile lookup)"});
            if (response.status == 429 || response.retry_after) {
                std::lock_guard lock(limits_mutex);
                limited_hosts.insert(host);
            }
            if (j.stop.stop_requested()) return;
            ++attempted;
            const bool denied = response.status == 202 || response.status == 401 || response.status == 403 ||
                                response.status == 429 || response.retry_after;
            const bool marker = profile_marker_matches(check.expected_status, check.marker, response.status, response.body);
            const SocialProfile requested{profile.platform, check.request_url};
            const bool page = (check.direct || !check.expected_status) &&
                              potential_social_account(requested, response.effective_url, response.status, response.body);
            const bool hit = !denied && (marker || page);
            if (hit) {
                ++found;
                j.add("Potential account · " + profile.platform, handle, profile.url,
                      {.provider = profile.platform, .query = handle,
                       .basis = marker ? "Bundled public profile rule matched" : "Public profile URL responded",
                       .scope = "Public profile URL"});
            }
            if (profile.platform == "Stripchat" && !hit) {
                const std::string result = response.status == 406 ? "HTTP 406 Not Acceptable (requested text/html)" :
                    response.status ? "HTTP " + std::to_string(response.status) : response.error;
                j.log("Stripchat: " + result + (denied ? " (blocked or rate limited)" : ""));
            }
            if (denied) ++blocked;
            else if (!response.status || response.status == 406 || response.status >= 500) ++unavailable;
            if (check.direct && j.coverage) {
                const auto state = hit ? CoverageState::Complete :
                                   denied ? CoverageState::Blocked :
                                   response.status == 404 || response.status == 410 ?
                                   CoverageState::Empty : CoverageState::Unavailable;
                j.coverage({profile.platform, "Public profile URL", state});
            }
        }
    };
    {
        const auto limit = j.settings.full_profile_catalog ? 16U : 4U;
        std::vector<std::jthread> workers;
        workers.reserve(limit);
        for (std::size_t i = 0; i < std::min<std::size_t>(limit, checks.size()); ++i) workers.emplace_back(worker);
    }
    j.log("Checked " + std::to_string(attempted) + " profile URLs · " + std::to_string(found) +
          " potential hits · " + std::to_string(blocked) + " blocked · " +
          std::to_string(unavailable) + " unavailable · " + std::to_string(skipped) + " catalog entries skipped · " +
          std::to_string(throttled) + " deferred by rate limits");
}
}  // namespace

const nlohmann::json& bundled_username_catalog() {
    static const auto catalog = nlohmann::json::parse(
        read_file((std::filesystem::path(MARK47_DATA_DIR) / "username-sites.json").string()));
    return catalog;
}

bool profile_marker_matches(long expected_status, std::string_view marker, long status, std::string_view body) {
    return expected_status > 0 && status == expected_status && body.find(marker) != body.npos;
}

std::vector<SocialProfile> social_profile_urls(std::string_view input) {
    const auto handle = normalize_username(input);
    if (handle.empty() || reserved(lowercase(handle))) return {};
    std::vector<SocialProfile> result;
    const auto encoded = url_encode(handle);
    const auto lower_handle = lowercase(handle);
    for (const auto& site : sites) {
        if (std::string_view(site.name) == "Vimeo") {
            // A numeric Vimeo path can be a video ID. Vanity profile URLs use letters and digits.
            if (handle.find_first_not_of("0123456789") == handle.npos || handle.find_first_of("._-") != handle.npos)
                continue;
        }
        if (std::string_view(site.name) == "Cash App" && handle.find_first_of("._-") != handle.npos) continue;
        if (std::string_view(site.name) == "Solo.to" &&
            (lower_handle == "register" || lower_handle == "pricing" || lower_handle == "how-it-works")) continue;
        result.push_back({site.name, site.prefix + encoded});
    }
    if (lower_handle != "www" && handle.size() <= 63 && handle.find_first_of("._") == handle.npos &&
        handle.front() != '-' && handle.back() != '-')
        result.push_back({"Carrd", "https://" + lower_handle + ".carrd.co/"});
    return result;
}

bool potential_social_account(const SocialProfile& profile, std::string_view effective_url,
                              long status, std::string_view body) {
    const bool stripchat = profile.platform == "Stripchat";
    const bool usable_status = stripchat ? status >= 200 && status < 300 && status != 202 : status == 200;
    if (!usable_status || body.find_first_not_of(" \t\r\n") == body.npos) return false;
    const auto expected = profile_key(profile.url);
    if (expected.empty() || (!effective_url.empty() && profile_key(effective_url) != expected)) return false;
    // Avoid treating an obvious login screen, challenge or soft 404 as a lead.
    const auto html = lowercase(body.substr(0, 96 * 1024));
    if (html.find("challenge-form") != html.npos || html.find("cf-chl-") != html.npos) return false;
    const auto start = html.find("<title");
    if (start == html.npos) return true;
    const auto open = html.find('>', start);
    const auto end = open == html.npos ? html.npos : html.find("</title", open + 1);
    if (end == html.npos) return true;
    const auto title = html.substr(open + 1, end - open - 1);
    if ((!stripchat && title == lowercase(profile.platform)) || title == "404" || title == "not found" ||
        (stripchat && (title.starts_with("404 ") || title.ends_with(" 404") ||
                       title.find("model not found") != title.npos || title.find("profile not found") != title.npos)) ||
        (profile.platform == "Carrd" && title.find("site not found") != title.npos)) return false;
    constexpr std::string_view rejection[]{
        "log in", "login", "sign in", "page not found", "user not found", "account suspended",
        "page isn", "page isn’t", "page unavailable", "access denied", "just a moment", "security check", "something went wrong"
    };
    return std::ranges::none_of(rejection, [&](auto text) { return title.find(text) != title.npos; });
}

const std::vector<Module>& social_modules() {
    static const std::vector<Module> modules = {
        {"Social profiles", "Check direct profiles and the bundled username catalog", Username, social_profiles},
    };
    return modules;
}
