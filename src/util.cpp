// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include <arpa/inet.h>
#include <phonenumbers/geocoding/phonenumber_offline_geocoder.h>
#include <phonenumbers/phonenumberutil.h>
#include <unicode/locid.h>
#include <unicode/unistr.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "http.h"
#include "nlohmann/json.hpp"
#include "osint.h"

std::string normalize_domain(std::string_view input) {
    for (std::string_view scheme : {"https://", "http://"}) {
        if (!input.starts_with(scheme)) continue;
        input.remove_prefix(scheme.size());
        if (input.ends_with('/')) input.remove_suffix(1);
        break;
    }
    if (input.ends_with('.')) input.remove_suffix(1);
    if (input.size() > 253 || input.find('.') == input.npos) return {};
    std::string result;
    while (!input.empty()) {
        const auto end = input.find('.');
        const auto label = input.substr(0, end);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return {};
        for (unsigned char ch : label) {
            if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) return {};
            result += static_cast<char>(ch);
        }
        if (end == input.npos) {
            if (!std::ranges::any_of(label, [](unsigned char ch) {
                return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
            })) return {};
            return result;
        }
        input.remove_prefix(end + 1);
        result += '.';
    }
    return {};
}

std::string normalize_username(std::string_view input) {
    std::string result;
    bool prefix_allowed = true;
    for (unsigned char ch : input) {
        if (std::isspace(ch)) continue;
        if (prefix_allowed && (ch == '@' || ch == '$')) { prefix_allowed = false; continue; }
        prefix_allowed = false;
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-'))
            return {};
        if (result.size() == 64) return {};
        result += static_cast<char>(ch);
    }
    if (result == "." || result == "..") return {};
    return result;
}

Type detect(std::string_view t) {
    if (!spotify_track_url(t).empty()) return SpotifyTrack;
    for (std::string_view scheme : {"https://", "http://"})
        if (t.starts_with(scheme) && !normalize_domain(t).empty()) return Domain;
    if (const auto first = t.find_first_not_of(" \t\r\n"); first != t.npos && (t[first] == '@' || t[first] == '$') &&
        !normalize_username(t).empty()) return Username;
    const std::string s(t);
    if (s.empty()) return Type(0);
    if (s.find_first_of(" \t\r\n") != std::string::npos && s.find_first_not_of("0123456789 +-().") != std::string::npos)
        return normalize_username(t).empty() ? Type(0) : Username;
    in_addr a4; in6_addr a6;
    if (inet_pton(AF_INET, s.c_str(), &a4) == 1 || inet_pton(AF_INET6, s.c_str(), &a6) == 1) return Ip;
    const size_t at = s.find('@');
    if (at != std::string::npos && at > 0 && s.find('@', at + 1) == std::string::npos &&
        s.find('.', at) != std::string::npos && s.back() != '.' && at + 1 < s.size() && s[at + 1] != '.')
        return Email;
    int digits = 0;
    bool phone_chars = true;
    for (char ch : s) {
        if (isdigit((unsigned char)ch)) digits++;
        else if (!strchr(" +-().", ch)) phone_chars = false;
    }
    if (phone_chars && digits >= 7 && digits <= 15) return Phone;
    if (!normalize_username(t).empty()) return Username;
    return Type(0);
}

const char* type_name(Type t) {
    switch (t) {
        case Phone: return "phone";
        case Email: return "email";
        case Ip: return "ip";
        case Username: return "username";
        case Domain: return "domain";
        case SpotifyTrack: return "spotify track";
    }
    return "unknown";
}

std::string data_path(const std::string& file) {
    const char* env = std::getenv("MARK47_DATA");
    if (env && *env) return std::string(env) + "/" + file;
    // Installed copy: <prefix>/bin/snitch reads <prefix>/share/snitch. A build-tree run falls through to the source data.
    std::error_code ec;
    const auto installed = std::filesystem::read_symlink("/proc/self/exe", ec).parent_path().parent_path() / "share/snitch" / file;
    if (!ec && std::filesystem::exists(installed, ec)) return installed.string();
    return std::string(MARK47_DATA_DIR) + "/" + file;
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot read " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<std::string> doh(const std::string& name, const std::string& rrtype, std::stop_token stop) {
    static const std::pair<const char*, int> codes[] = {{"A", 1}, {"PTR", 12}, {"MX", 15}, {"TXT", 16}, {"AAAA", 28}};
    int code = 0;
    for (auto& [n, c] : codes) if (rrtype == n) code = c;
    const Response r = http_get("https://cloudflare-dns.com/dns-query?name=" + url_encode(name) + "&type=" + rrtype, stop,
                                {.headers = {"accept: application/dns-json"}, .min_interval_s = 0});
    if (r.status != 200) throw std::runtime_error("DoH " + rrtype + " " + name + ": " + (r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error));
    std::vector<std::string> out;
    const auto j = nlohmann::json::parse(r.body);
    if (!j.contains("Answer")) return out;
    for (const auto& a : j["Answer"]) {
        if (a.value("type", 0) != code) continue;  // skip CNAME hops
        std::string d = a.value("data", "");
        if (code == 16) {  // TXT: "\"part1\" \"part2\"" -> part1part2
            std::string joined;
            bool in = false;
            for (char ch : d) { if (ch == '"') in = !in; else if (in) joined += ch; }
            d = joined.empty() ? d : joined;
        }
        if (!d.empty() && d.back() == '.' && code != 16) d.pop_back();
        out.push_back(d);
    }
    return out;
}

std::string html_text(std::string_view h) {
    static const std::pair<const char*, const char*> ents[] = {
        {"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", "\""}, {"&#39;", "'"}, {"&#x27;", "'"}, {"&nbsp;", " "}, {"&#x2F;", "/"}};
    std::string out;
    for (size_t i = 0; i < h.size(); i++) {
        if (h[i] == '<') {
            const size_t e = h.find('>', i);
            if (e == std::string_view::npos) break;
            // Inline tags join text ("<b>Co</b>'s"); anything else (div, p, br, li...) separates it.
            std::string_view name = h.substr(i + 1, e - i - 1);
            if (!name.empty() && name[0] == '/') name.remove_prefix(1);
            name = name.substr(0, name.find_first_of(" \t/"));
            static const std::string_view inl[] = {"b", "i", "em", "strong", "span", "a", "mark", "u", "small", "sup", "sub", "wbr"};
            if (std::find(std::begin(inl), std::end(inl), name) == std::end(inl)) out += ' ';
            i = e;
            continue;
        }
        if (h[i] == '&') {
            bool hit = false;
            for (auto& [k, v] : ents)
                if (h.substr(i, strlen(k)) == k) { out += v; i += strlen(k) - 1; hit = true; break; }
            if (!hit && i + 2 < h.size() && h[i + 1] == '#') {  // &#NNN;
                const size_t semi = h.find(';', i);
                if (semi != std::string_view::npos && semi - i <= 7) {
                    const long cp = strtol(std::string(h.substr(i + 2, semi - i - 2)).c_str(), nullptr, 10);
                    out += cp >= 32 && cp < 127 ? char(cp) : '?';
                    i = semi;
                    hit = true;
                }
            }
            if (hit) continue;
        }
        out += h[i];
    }
    std::string col;  // collapse whitespace
    for (char ch : out) {
        const bool sp = isspace((unsigned char)ch);
        if (sp && (col.empty() || col.back() == ' ')) continue;
        col += sp ? ' ' : ch;
    }
    if (!col.empty() && col.back() == ' ') col.pop_back();
    return col;
}

std::vector<std::string> find_emails(std::string_view s) {
    auto local = [](char ch) { return isalnum((unsigned char)ch) || strchr("._%+-", ch); };
    auto dom = [](char ch) { return isalnum((unsigned char)ch) || ch == '.' || ch == '-'; };
    std::vector<std::string> out;
    for (size_t at = s.find('@'); at != std::string_view::npos; at = s.find('@', at + 1)) {
        size_t b = at, e = at + 1;
        while (b > 0 && local(s[b - 1])) b--;
        while (e < s.size() && dom(s[e])) e++;
        while (e > at + 1 && (s[e - 1] == '.' || s[e - 1] == '-')) e--;
        while (b < at && s[b] == '.') b++;
        if (b == at) continue;
        std::string m(s.substr(b, e - b));
        const size_t dot = m.rfind('.');
        if (dot == std::string::npos || dot < m.find('@')) continue;
        const std::string tld = m.substr(dot + 1);
        if (tld.size() < 2 || !std::all_of(tld.begin(), tld.end(), [](char ch) { return isalpha((unsigned char)ch); })) continue;
        if (tld == "png" || tld == "jpg" || tld == "gif" || tld == "webp" || tld == "svg") continue;  // "icon@2x.png"
        std::transform(m.begin(), m.end(), m.begin(), [](unsigned char ch) { return char(tolower(ch)); });
        if (std::find(out.begin(), out.end(), m) == out.end()) out.push_back(m);
    }
    return out;
}

std::vector<std::string> find_phones(std::string_view s) {
    std::vector<std::string> out;
    for (size_t i = 0; i < s.size();) {
        const bool start = isdigit((unsigned char)s[i]) || s[i] == '+' || s[i] == '(';
        if (!start || (i > 0 && isalnum((unsigned char)s[i - 1]))) { i++; continue; }
        size_t e = i;
        int digits = 0;
        while (e < s.size() && (isdigit((unsigned char)s[e]) || strchr(" -().+", s[e]))) {
            if (s[e] == ' ' && e + 1 < s.size() && s[e + 1] == ' ') break;
            digits += isdigit((unsigned char)s[e]) != 0;
            e++;
        }
        while (e > i && !isdigit((unsigned char)s[e - 1])) e--;
        if (digits >= 10 && digits <= 15 && (e >= s.size() || !isalnum((unsigned char)s[e]))) {
            std::string m(s.substr(i, e - i));
            if (std::find(out.begin(), out.end(), m) == out.end()) out.push_back(m);
        }
        i = std::max(e, i + 1);
    }
    return out;
}

PhoneInfo phone_info(const std::string& number, const std::string& default_region) {
    using namespace i18n::phonenumbers;
    const PhoneNumberUtil* u = PhoneNumberUtil::GetInstance();
    PhoneNumber n;
    PhoneInfo p;
    if (u->Parse(number, default_region, &n) != PhoneNumberUtil::NO_PARSING_ERROR) return p;
    p.ok = true;
    p.valid = u->IsValidNumber(n);
    u->Format(n, PhoneNumberUtil::E164, &p.e164);
    u->Format(n, PhoneNumberUtil::INTERNATIONAL, &p.international);
    u->Format(n, PhoneNumberUtil::NATIONAL, &p.national);
    p.digits = p.e164.substr(1);
    u->GetRegionCodeForNumber(n, &p.region);
    switch (u->GetNumberType(n)) {
        case PhoneNumberUtil::FIXED_LINE: p.type = "landline"; break;
        case PhoneNumberUtil::MOBILE: p.type = "mobile"; break;
        case PhoneNumberUtil::FIXED_LINE_OR_MOBILE: p.type = "landline or mobile"; break;
        case PhoneNumberUtil::TOLL_FREE: p.type = "toll free"; break;
        case PhoneNumberUtil::PREMIUM_RATE: p.type = "premium rate"; break;
        case PhoneNumberUtil::SHARED_COST: p.type = "shared cost"; break;
        case PhoneNumberUtil::VOIP: p.type = "VoIP"; break;
        case PhoneNumberUtil::PERSONAL_NUMBER: p.type = "personal number"; break;
        case PhoneNumberUtil::PAGER: p.type = "pager"; break;
        case PhoneNumberUtil::UAN: p.type = "UAN"; break;
        case PhoneNumberUtil::VOICEMAIL: p.type = "voicemail"; break;
        default: p.type = "unknown"; break;
    }
    static const PhoneNumberOfflineGeocoder geo;  // loads its tables once
    p.location = geo.GetDescriptionForNumber(n, icu::Locale("en"));
    if (!p.region.empty() && p.region != "ZZ") {
        icu::UnicodeString name;
        icu::Locale("", p.region.c_str()).getDisplayCountry(icu::Locale("en"), name);
        name.toUTF8String(p.country);
    }
    return p;
}
