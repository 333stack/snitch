// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include <openssl/evp.h>

#include <algorithm>
#include <set>
#include <stdexcept>

#include "http.h"
#include "modules.h"

using json = nlohmann::json;

static std::string domain_of(const std::string& email) { return email.substr(email.find('@') + 1); }

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(tolower(c)); });
    return s;
}

static std::string sha256_hex(const std::string& s) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    EVP_Digest(s.data(), s.size(), md, &len, EVP_sha256(), nullptr);
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (unsigned i = 0; i < len; i++) { out += hex[md[i] >> 4]; out += hex[md[i] & 15]; }
    return out;
}

std::string mail_provider(const std::vector<std::string>& mx) {
    static const std::pair<const char*, const char*> known[] = {
        {"google.com", "Google Workspace / Gmail"}, {"googlemail.com", "Google Workspace / Gmail"},
        {"outlook.com", "Microsoft 365 / Outlook"}, {"protonmail.ch", "Proton Mail"}, {"proton.me", "Proton Mail"},
        {"yahoodns.net", "Yahoo"}, {"icloud.com", "iCloud"}, {"zoho.", "Zoho Mail"}, {"mimecast.com", "Mimecast (filter)"},
        {"pphosted.com", "Proofpoint (filter)"}, {"messagelabs.com", "Broadcom/Symantec (filter)"}, {"tutanota.de", "Tuta"},
        {"secureserver.net", "GoDaddy"}, {"mailgun.org", "Mailgun"}, {"fastmail.com", "Fastmail"}, {"yandex.", "Yandex"},
        {"mail.ru", "Mail.ru"}, {"gmx.", "GMX"}, {"emailsrvr.com", "Rackspace"}, {"barracudanetworks.com", "Barracuda (filter)"}};
    for (const auto& m : mx)
        for (auto& [k, v] : known)
            if (lower(m).find(k) != std::string::npos) return v;
    return mx.empty() ? "" : "self-hosted / other";
}

static void dns(const Job& j) {
    const std::string d = domain_of(j.target);
    std::vector<std::string> mx;
    for (auto& r : doh(d, "MX", j.stop)) {
        mx.push_back(r.substr(r.find(' ') + 1));  // "10 mx.example.com"
        j.add("MX", r);
    }
    if (mx.empty()) j.add("MX", "none: domain can't receive mail (address is likely fake)");
    else j.add("mail provider", mail_provider(mx));
    for (auto& t : doh(d, "TXT", j.stop)) {
        if (t.starts_with("v=spf1")) j.add("SPF", t);
        else if (t.find("verification") != std::string::npos || t.find("-site-") != std::string::npos)
            j.add("TXT (services used)", t);  // google-site-verification, MS=, atlassian-domain-verification...
    }
    for (auto& t : doh("_dmarc." + d, "TXT", j.stop)) j.add("DMARC", t);
    if (const auto domain = normalize_domain(d); !domain.empty())
        j.pivot("domain", domain, "https://rdap.org/domain/" + domain,
                {.provider = "Email domain", .basis = "Domain portion of queried email"}, Domain);
}

static void disposable(const Job& j) {
    const Response r = http_get("https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf", j.stop);
    if (r.status != 200) throw std::runtime_error(r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    const bool hit = ("\n" + r.body + "\n").find("\n" + lower(domain_of(j.target)) + "\n") != std::string::npos;
    j.add("disposable", hit ? "YES: throwaway mail domain" : "no");
}

static void gravatar(const Job& j) {
    const std::string h = sha256_hex(lower(j.target));
    const Response r = http_get("https://api.gravatar.com/v3/profiles/" + h, j.stop);
    if (r.status == 404) { j.log("no Gravatar profile"); return; }
    if (r.status != 200) throw std::runtime_error(r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    const json d = json::parse(r.body);
    j.add("profile", d.value("display_name", ""), d.value("profile_url", ""));
    j.add("avatar", d.value("avatar_url", ""), d.value("avatar_url", ""));
    for (const char* f : {"location", "description", "job_title", "company", "pronouns"})
        if (!d.value(f, "").empty()) j.add(f, d.value(f, ""));
    for (const auto& a : d.value("verified_accounts", json::array()))
        j.add("linked " + a.value("service_label", "account"), a.value("url", ""), a.value("url", ""));
}

static void pgp(const Job& j) {
    const std::string url = "https://keys.openpgp.org/vks/v1/by-email/" + url_encode(j.target);
    const Response r = http_get(url, j.stop);
    if (r.status == 404) { j.log("no verified key on keys.openpgp.org"); return; }
    if (r.status != 200) throw std::runtime_error(r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    j.add("PGP key", "published on keys.openpgp.org", url);
}

static void github_commits(const Job& j) {
    const Response r = http_get("https://api.github.com/search/commits?per_page=50&q=author-email:" + url_encode(j.target), j.stop,
                                {.headers = {"Accept: application/vnd.github+json"}});
    if (r.status == 403 || r.status == 429) throw std::runtime_error("GitHub rate limit (10 searches/min without a token)");
    if (r.status != 200) throw std::runtime_error(r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    const json d = json::parse(r.body);
    std::set<std::string> logins, names, repos;
    for (const auto& it : d.value("items", json::array())) {
        if (it.contains("author") && it["author"].is_object()) logins.insert(it["author"].value("login", ""));
        names.insert(it["commit"]["author"].value("name", ""));
        repos.insert(it["repository"].value("full_name", ""));
    }
    if (d.value("total_count", 0) == 0) { j.log("no public commits with this author email"); return; }
    j.add("commits (incl. forks)", std::to_string(d.value("total_count", 0)), "https://github.com/search?type=commits&q=author-email:" + url_encode(j.target));
    for (auto& l : logins) if (!l.empty()) j.pivot("GitHub user", l);
    for (auto& n : names) if (!n.empty()) j.add("commit name", n);
    for (auto& rp : repos) if (!rp.empty()) j.add("repo", rp, "https://github.com/" + rp);
}

static void pivots(const Job& j) {
    std::string local = j.target.substr(0, j.target.find('@'));
    if (const size_t plus = local.find('+'); plus != std::string::npos) {
        j.add("plus tag", local.substr(plus + 1));  // often names the site the address was given to
        local.resize(plus);
    }
    j.pivot("username candidate", local);
    if (local.find('.') != std::string::npos) {  // first.last -> firstlast, first_last
        std::string joined = local, under = local;
        joined.erase(std::remove(joined.begin(), joined.end(), '.'), joined.end());
        std::replace(under.begin(), under.end(), '.', '_');
        j.pivot("username candidate", joined);
        j.pivot("username candidate", under);
    }
}

const std::vector<Module>& email_modules() {
    static const std::vector<Module> m = {
        {"Mail DNS", "MX, provider, SPF, DMARC, service verification records", Email, dns},
        {"Disposable", "Throwaway-domain list (disposable-email-domains)", Email, disposable},
        {"Gravatar", "Public profile + linked accounts", Email, gravatar},
        {"PGP keys", "keys.openpgp.org (verified addresses only)", Email, pgp},
        {"GitHub commits", "Public commits by this author email -> GitHub user, name, repos", Email, github_commits},
        {"Email pivots", "Username candidates from the local part, plus-tag", Email, pivots},
    };
    return m;
}
