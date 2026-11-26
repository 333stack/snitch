// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include "findings.h"
#include "http.h"
#include "modules.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <tuple>

namespace {
std::string lower(std::string_view text) {
    std::string result(text);
    for (char& ch : result) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return result;
}

std::string github_profile(std::string_view url) {
    const auto scheme = url.find("://");
    if (scheme == url.npos || (url.substr(0, scheme) != "http" && url.substr(0, scheme) != "https")) return {};
    url.remove_prefix(scheme + 3);
    const auto slash = url.find('/');
    if (slash == url.npos) return {};
    const auto host = lower(url.substr(0, slash));
    if (host != "github.com" && host != "www.github.com") return {};
    url.remove_prefix(slash + 1);

    const auto query = url.find_first_of("?#");
    const auto suffix = query == url.npos ? std::string_view{} : url.substr(query);
    auto name = url.substr(0, query);
    if (name.ends_with('/')) name.remove_suffix(1);
    // Only profile tabs and fragments. Repository and other path segments identify distinct pages.
    const auto tab = suffix.substr(0, suffix.find_first_of("&#"));
    if (!tab.empty() && tab != "?tab=repositories" && tab != "?tab=stars" &&
        tab != "?tab=projects" && tab != "?tab=packages" && tab != "?tab=overview" &&
        tab != "?tab=followers" && tab != "?tab=following" && tab != "?tab=achievements") return {};
    if (name.empty() || name.size() > 39 || name.front() == '-' || name.back() == '-' ||
        !std::ranges::all_of(name, [](unsigned char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                   (ch >= '0' && ch <= '9') || ch == '-';
        })) return {};
    const auto account = lower(name);
    // Known top-level product routes can also look like account names.
    static const std::set<std::string_view> reserved{
        "about", "account", "apps", "collections", "contact", "copilot", "dashboard",
        "enterprise", "events", "explore", "features", "issues", "login", "logout",
        "marketplace", "new", "notifications", "orgs", "organizations", "pricing",
        "pulls", "search", "security", "settings", "signup", "sponsors", "topics", "trending"
    };
    if (reserved.contains(account)) return {};
    return "https://github.com/" + account;
}

int source_priority(const Finding& f) {
    if (f.evidence.basis == "Imported WhatsMyName CSV hit") return -3;
    if (f.module == "Social profiles" || (f.module == "Dorks" && f.key.starts_with("Public match · "))) return -2;
    if ((f.module == "GitHub" && f.key == "profile") || f.key.starts_with("Potential account · ")) return -1;
    if (f.module == "Dorks") return f.key.starts_with("weak ") ? 3 : 1;
    return f.module == "Lookup links" ? 2 : 0;
}
}  // namespace

std::string finding_text(std::string_view text) {
    std::string result;
    bool space = false;
    for (unsigned char ch : text) {
        if (std::isspace(ch)) { space = !result.empty(); continue; }
        if (ch < 32 || ch == 127) continue;
        if (space) result += ' ';
        result += static_cast<char>(ch);
        space = false;
    }
    return result;
}

std::vector<FindingGroup> group_findings(const std::vector<Finding>& findings,
                                         std::string_view filter, bool hide_weak) {
    using Key = std::tuple<std::size_t, std::string, std::string, std::string>;
    std::map<Key, std::size_t> by_key;
    std::vector<FindingGroup> groups;
    std::set<std::tuple<std::size_t, std::string, std::string, std::string, std::string, bool>> seen;
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        if (hide_weak && f.module == "Dorks" && f.key.starts_with("weak ")) continue;
        if (!seen.emplace(f.run_id, f.module, f.key, f.value, f.url, f.pivot).second) continue;
        const auto profile = f.pivot ? std::string{} : github_profile(f.url);
        Key key{f.run_id, f.module, f.key, f.value};
        if (f.pivot) key = {f.run_id, "pivot", type_name(f.pivot_type ? f.pivot_type : detect(f.value)), f.value};
        else if (!f.url.empty() && f.module != "Spotify credits") key = {f.run_id, "url", f.module == auto_dork_section || f.module == whatsmyname_csv_section ? f.module : "",
                                       profile.empty() ? f.url : profile};
        const auto [it, inserted] = by_key.try_emplace(std::move(key), groups.size());
        if (inserted) groups.push_back({i, {i}, profile});
        else {
            auto& members = groups[it->second].members;
            members.push_back(i);
            if (source_priority(f) < source_priority(findings[members.front()]))
                std::swap(members.front(), members.back());
        }
    }

    const auto query = lower(finding_text(filter));
    if (!query.empty()) std::erase_if(groups, [&](const FindingGroup& g) {
        return lower(g.profile_url).find(query) == std::string::npos &&
               std::ranges::none_of(g.members, [&](std::size_t i) {
                   const auto& f = findings[i];
                   return lower(finding_text(f.module + " " + f.key + " " + f.value + " " + f.url)).find(query) != std::string::npos;
               });
    });
    std::map<std::string_view, std::size_t> order;
    for (const auto& m : modules()) {
        if (std::string_view(m.name) == "Dorks") order.try_emplace(auto_dork_section, order.size());
        order.try_emplace(m.name, order.size());
    }
    auto rank = [&](std::string_view module) {
        const auto it = order.find(module);
        return it == order.end() ? order.size() : it->second;
    };
    std::ranges::stable_sort(groups, [&](const FindingGroup& a, const FindingGroup& b) {
        const auto& left = findings[a.members.front()];
        const auto& right = findings[b.members.front()];
        if (left.run_id != right.run_id) return left.run_id > right.run_id;
        if (left.module != right.module)
            return std::tuple{rank(left.module), left.module} < std::tuple{rank(right.module), right.module};
        if (left.module == "Dorks" && (source_priority(left) == -2 || source_priority(right) == -2))
            return source_priority(left) < source_priority(right);
        return !a.profile_url.empty() && b.profile_url.empty();
    });
    return groups;
}


std::optional<Finding> whatsmyname_fallback(std::string_view target, std::size_t run_id) {
    const auto username = normalize_username(target);
    if (username.empty()) return std::nullopt;
    return Finding{whatsmyname_fallback_name, "Open WhatsMyName in browser", username,
                   "https://whatsmyname.app/?q=" + url_encode(username), false, run_id,
                   {.provider = "WhatsMyName.app", .query = username, .basis = "Navigation link"}};
}
