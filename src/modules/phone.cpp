// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>

#include <phonenumbers/phonenumbermatch.h>
#include <phonenumbers/phonenumbermatcher.h>
#include <phonenumbers/phonenumberutil.h>

#include "modules.h"

namespace {
struct ProfileRule {
    std::string_view host, service, prefix;
};

constexpr ProfileRule profiles[] = {
    {"facebook.com", "Facebook", ""}, {"instagram.com", "Instagram", ""},
    {"x.com", "X", ""}, {"twitter.com", "X", ""}, {"linkedin.com", "LinkedIn", "in/"},
    {"linkedin.com", "LinkedIn", "company/"}, {"tiktok.com", "TikTok", "@"},
    {"youtube.com", "YouTube", "@"}, {"youtube.com", "YouTube", "channel/"},
    {"threads.net", "Threads", "@"}, {"threads.com", "Threads", "@"},
    {"reddit.com", "Reddit", "user/"}, {"reddit.com", "Reddit", "u/"},
    {"bsky.app", "Bluesky", "profile/"}, {"mastodon.social", "Mastodon", "@"},
    {"github.com", "GitHub", ""}, {"gitlab.com", "GitLab", ""},
    {"pinterest.com", "Pinterest", ""}, {"twitch.tv", "Twitch", ""},
    {"soundcloud.com", "SoundCloud", ""}, {"linktr.ee", "Linktree", ""},
    {"medium.com", "Medium", "@"}, {"dev.to", "DEV Community", ""},
    {"behance.net", "Behance", ""}, {"dribbble.com", "Dribbble", ""},
};

}  // namespace

bool text_matches_phone(const std::string& text, const PhoneInfo& target) {
    if (!target.valid) return false;
    using namespace i18n::phonenumbers;
    const auto& util = *PhoneNumberUtil::GetInstance();
    PhoneNumberMatcher matcher(util, text, target.region, PhoneNumberMatcher::VALID, 80);
    PhoneNumberMatch match;
    while (matcher.Next(&match)) {
        std::string normalized;
        util.Format(match.number(), PhoneNumberUtil::E164, &normalized);
        if (normalized == target.e164) return true;
    }
    return false;
}

PublicPhoneProfile public_phone_profile(const SearchResult& result, const PhoneInfo& phone) {
    if (!phone.valid) return {};
    std::string_view url = result.url;
    if (url.starts_with("https://")) url.remove_prefix(8);
    else if (url.starts_with("http://")) url.remove_prefix(7);
    else return {};
    const auto slash = url.find('/');
    if (slash == url.npos) return {};
    std::string host(url.substr(0, slash));
    for (char& ch : host) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    if (host.starts_with("www.")) host.erase(0, 4);
    if (host == "m.facebook.com") host = "facebook.com";
    const auto path = url.substr(slash + 1, url.find_first_of("?#", slash) - slash - 1);
    for (const auto& rule : profiles) {
        if (host != rule.host || !path.starts_with(rule.prefix)) continue;
        auto handle = path.substr(rule.prefix.size());
        if (handle.ends_with('/')) handle.remove_suffix(1);
        if (handle.empty() || handle.size() > 100 || !std::ranges::all_of(handle, [](unsigned char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                   (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
        })) continue;
        std::string route(handle);
        for (char& ch : route) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        static constexpr std::string_view reserved[] = {
            ".", "..", "about", "account", "accounts", "contact", "directory", "discover",
            "events", "explore", "feed", "help", "home", "jobs", "login", "logout", "marketplace",
            "messages", "notifications", "pricing", "privacy", "search", "settings", "signup",
            "stories", "terms", "topics", "trending", "watch", "videos", "profile.php"
        };
        if (std::ranges::find(reserved, route) != std::end(reserved)) continue;
        if (text_matches_phone(result.title, phone) || text_matches_phone(result.snippet, phone))
            return {std::string(rule.service), std::string(handle)};
    }
    return {};
}

std::string carrier_for_prefix(std::istream& records, std::string_view digits, std::string* dataset) {
    std::string best;
    std::size_t longest = 0;
    for (std::string line; std::getline(records, line);) {
        const std::string_view row(line);
        if (dataset && row.starts_with("# Dataset: ")) {
            *dataset = row.substr(11, row.find_last_not_of("\r") + 1 - 11);
            continue;
        }
        const auto sep = row.find('|');
        if (sep == row.npos || sep <= longest || !digits.starts_with(row.substr(0, sep))) continue;
        auto carrier = row.substr(sep + 1);
        const auto first = carrier.find_first_not_of(" \t\r");
        if (first == carrier.npos) continue;
        carrier = carrier.substr(first, carrier.find_last_not_of(" \t\r") - first + 1);
        best = carrier;
        longest = sep;
    }
    return best;
}

static void number(const Job& j) {
    const PhoneInfo p = phone_info(j.target, j.settings.region);
    if (!p.ok) throw std::runtime_error("not a parseable number (set the default region in Settings for numbers without +)");
    j.add("valid", p.valid ? "yes" : "NO: not a number the national plan assigns (fake, unallocated or mistyped)");
    j.add("E.164", p.e164);
    j.add("international", p.international);
    j.add("national", p.national);
    j.add("country", p.country + " (" + p.region + ")");
    j.add("line type", p.type);
    if (p.valid) {
        std::ifstream records(data_path("carrier-prefixes.txt"));
        if (!records) {
            j.add("original carrier", "Carrier data unavailable (see documentation)");
            j.add("carrier coverage", "No local carrier table");
        } else {
            std::string dataset;
            const auto carrier = carrier_for_prefix(records, p.digits, &dataset);
            j.add("original carrier", carrier.empty() ? "No matching prefix" : carrier);
            j.add("carrier dataset", dataset.empty() ? "Unversioned local table" : dataset);
            j.add("carrier coverage", carrier.empty() ? "Number range missing" : "Original prefix assignment only");
        }
    }
    if (!p.location.empty()) j.add("area", p.location + " (where the number was assigned; ported/mobile numbers move)");
}

const std::vector<Module>& phone_modules() {
    static const std::vector<Module> m = {
        {"Number info", "Validity, formats, country, line type, area (libphonenumber, offline)", Phone, number},
    };
    return m;
}
