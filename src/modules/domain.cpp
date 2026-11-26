// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include "modules.h"

#include <algorithm>
#include <set>
#include <sstream>
#include <stdexcept>

#include "http.h"

using json = nlohmann::json;

std::vector<std::string> domain_dns_answers(const json& response, int record_type) {
    const int status = response.at("Status");
    if (auto comment = response.find("Comment"); comment != response.end()) {
        auto text = comment->dump();
        for (char& ch : text) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
        for (std::string_view policy : {"blocked", "censored", "filtered", "prohibited", "stale"})
            if (text.find(policy) != text.npos) throw std::runtime_error("DNS response limited by resolver policy");
    }
    if (response.value("TC", false) || (status != 0 && status != 3))
        throw std::runtime_error("DNS response incomplete (status " + std::to_string(status) + ")");
    if (status == 3) return {};
    const auto answers = response.value("Answer", json::array());
    if (!answers.is_array()) throw std::runtime_error("invalid DNS answer list");
    std::set<std::string> seen;
    std::vector<std::string> values;
    for (const auto& answer : answers) {
        if (answer.at("type") != record_type) continue;
        const std::string data = answer.at("data");
        if (!data.empty() && seen.insert(data).second) values.push_back(data);
    }
    return values;
}

std::vector<Finding> domain_certificate_hits(const json& response, std::string_view target) {
    if (!response.is_array()) throw std::runtime_error("invalid certificate search response");
    std::vector<Finding> hits;
    std::set<std::pair<std::string, std::string>> seen;
    const auto suffix = "." + std::string(target);
    for (const auto& cert : response) {
        const auto certificate_id = cert.value("id", 0LL);
        if (certificate_id <= 0) continue;
        const auto date = cert.value("not_before", "");
        std::istringstream names(cert.value("name_value", ""));
        for (std::string name; std::getline(names, name);) {
            const bool wildcard = name.starts_with("*.");
            const auto domain = normalize_domain(wildcard ? name.substr(2) : name);
            if (domain.empty() || (domain != target && !domain.ends_with(suffix))) continue;
            name = wildcard ? "*." + domain : domain;
            if (!seen.emplace(name, date).second) continue;
            hits.push_back({{}, "Historical certificate name", name, "https://crt.sh/?id=" + std::to_string(certificate_id),
                            false, 0, {.provider = "crt.sh", .query = std::string(target),
                            .basis = "Certificate name; current DNS unverified", .scope = "Certificate history", .source_date = date}});
            if (hits.size() == 24) return hits;
        }
    }
    return hits;
}

namespace {
void coverage(const Job& j, std::string provider, std::string scope, CoverageState state, bool exhaustive = false) {
    if (j.coverage && !j.stop.stop_requested())
        j.coverage({std::move(provider), std::move(scope), state, exhaustive});
}

CoverageState failure(const Response& response) {
    return response.status == 403 || response.status == 429 || response.retry_after ?
           CoverageState::Blocked : CoverageState::Unavailable;
}

void domain_dns(const Job& j) {
    struct Record { const char* name; int number; };
    static constexpr Record records[] = {{"A", 1}, {"AAAA", 28}, {"CNAME", 5}, {"NS", 2},
                                          {"MX", 15}, {"TXT", 16}, {"CAA", 257}, {"DMARC", 16}};
    std::vector<std::string> mx;
    for (const auto& r : records) {
        if (j.stop.stop_requested()) return;
        const std::string name = std::string_view(r.name) == "DMARC" ? "_dmarc." + j.target : j.target;
        const std::string url = "https://cloudflare-dns.com/dns-query?name=" + url_encode(name) +
                                "&type=" + std::to_string(r.number);
        const auto response = http_get(url, j.stop, {.headers = {"Accept: application/dns-json"}, .min_interval_s = 0});
        if (j.stop.stop_requested()) return;
        if (response.status != 200) {
            coverage(j, "Cloudflare DoH", r.name, failure(response));
            j.log(std::string(r.name) + ": " + (response.error.empty() ? "HTTP " + std::to_string(response.status) : response.error));
            continue;
        }
        try {
            const auto values = domain_dns_answers(json::parse(response.body), r.number);
            const Evidence evidence{.provider = "Cloudflare DoH", .query = name + " " + r.name,
                                    .basis = "Current DNS answer", .scope = r.name};
            for (const auto& value : values) {
                std::string destination = value;
                if (r.number == 15) {
                    const auto space = value.find(' ');
                    destination = space == value.npos ? "" : value.substr(space + 1);
                    mx.push_back(destination);
                }
                if ((r.number == 1 || r.number == 28) && detect(destination) == Ip) {
                    j.pivot(r.name, value, url, evidence, Ip);
                } else if (r.number == 2 || r.number == 5 || r.number == 15) {
                    const auto domain = normalize_domain(destination);
                    j.add(r.name, value, url, evidence);
                    if (!domain.empty() && domain != j.target)
                        j.pivot(std::string(r.name) + " host", domain, url, evidence, Domain);
                } else if (std::string_view(r.name) == "TXT" &&
                           (value.starts_with("v=spf1") || value.starts_with("\"v=spf1"))) {
                    j.add("SPF", value, url, evidence);
                } else {
                    j.add(r.name, value, url, evidence);
                }
            }
            coverage(j, "Cloudflare DoH", r.name, values.empty() ? CoverageState::Empty : CoverageState::Complete, true);
        } catch (const json::exception& e) {
            coverage(j, "Cloudflare DoH", r.name, CoverageState::Unavailable);
            j.log(std::string(r.name) + ": malformed response (" + e.what() + ")");
        } catch (const std::runtime_error& e) {
            coverage(j, "Cloudflare DoH", r.name, CoverageState::Unavailable);
            j.log(std::string(r.name) + ": " + e.what());
        }
    }
    if (!mx.empty() && !j.stop.stop_requested()) {
        const auto provider = mail_provider(mx);
        if (!provider.empty()) j.add("Mail provider", provider, "https://cloudflare-dns.com/dns-query?name=" +
                                    url_encode(j.target) + "&type=15", {.provider = "Cloudflare DoH", .query = j.target + " MX",
                                    .basis = "Inferred from MX hosts", .scope = "MX"});
    }
}

void domain_rdap(const Job& j) {
    const auto url = "https://rdap.org/domain/" + url_encode(j.target);
    const auto response = http_get(url, j.stop);
    if (j.stop.stop_requested()) return;
    if (response.status != 200) {
        coverage(j, "RDAP", "Domain registration", response.status == 404 ? CoverageState::Empty : failure(response));
        j.log("Domain RDAP: " + (response.error.empty() ? "HTTP " + std::to_string(response.status) : response.error));
        return;
    }
    try {
        const auto d = json::parse(response.body);
        if (d.value("objectClassName", "") != "domain") throw std::runtime_error("invalid RDAP domain record");
        const Evidence evidence{.provider = "RDAP", .query = j.target, .basis = "Registry response",
                                .scope = "Domain registration", .source_origin = response.effective_url};
        j.add("Registry domain", d.value("ldhName", j.target), url, evidence);
        for (const auto& status : d.value("status", json::array())) j.add("Registry status", status.get<std::string>(), url, evidence);
        for (const auto& event : d.value("events", json::array())) {
            const auto date = event.value("eventDate", "");
            if (date.empty()) continue;
            auto dated = evidence;
            dated.source_date = date;
            j.add("Registry " + event.value("eventAction", "event"), date, url, dated);
        }
        for (const auto& entity : d.value("entities", json::array())) {
            const auto roles = entity.value("roles", std::vector<std::string>{});
            if (std::ranges::find(roles, "registrar") == roles.end()) continue;
            const auto handle = entity.value("handle", "");
            if (!handle.empty()) j.add("Registrar ID", handle, url, evidence);
            const auto card = entity.value("vcardArray", json::array());
            if (card.is_array() && card.size() >= 2 && card[1].is_array())
                for (const auto& row : card[1])
                    if (row.is_array() && row.size() >= 4 && row[0] == "fn" && row[3].is_string())
                        j.add("Registrar", row[3].get<std::string>(), url, evidence);
        }
        coverage(j, "RDAP", "Domain registration", CoverageState::Complete);
    } catch (const std::exception& e) {
        coverage(j, "RDAP", "Domain registration", CoverageState::Unavailable);
        j.log(e.what());
    }
}

void domain_certificates(const Job& j) {
    const std::string query = "https://crt.sh/?q=" + url_encode(j.target) + "&output=json";
    const auto r = http_get(query, j.stop, {.timeout_s = 25});
    if (j.stop.stop_requested()) return;
    if (r.status != 200) {
        coverage(j, "crt.sh", "Certificate history", failure(r));
        j.log("Certificate history: " + (r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error));
        return;
    }
    try {
        auto hits = domain_certificate_hits(json::parse(r.body), j.target);
        for (auto& hit : hits) j.emit(std::move(hit));
        coverage(j, "crt.sh", "Certificate history", hits.empty() ? CoverageState::Empty : CoverageState::Complete);
    } catch (const std::exception& e) {
        coverage(j, "crt.sh", "Certificate history", CoverageState::Unavailable);
        j.log(e.what());
    }
}

void domain_archive(const Job& j) {
    const std::string url = "https://web.archive.org/cdx/search/cdx?output=json&fl=timestamp,original"
                            "&filter=statuscode:200&collapse=timestamp:6&limit=12&url=" + url_encode(j.target + "/");
    const auto r = http_get(url, j.stop, {.timeout_s = 25});
    if (j.stop.stop_requested()) return;
    if (r.status != 200) {
        coverage(j, "Internet Archive", "Homepage captures", failure(r));
        j.log("Archive: " + (r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error));
        return;
    }
    try {
        const auto rows = json::parse(r.body);
        if (!rows.is_array()) throw std::runtime_error("invalid archive response");
        int captured = 0;
        for (std::size_t i = 1; i < rows.size() && i <= 12; ++i) {
            const std::string stamp = rows[i].at(0), original = rows[i].at(1);
            if (stamp.size() != 14 || stamp.find_first_not_of("0123456789") != stamp.npos ||
                !(original.starts_with("https://") || original.starts_with("http://"))) continue;
            const auto date = stamp.substr(0, 4) + "-" + stamp.substr(4, 2) + "-" + stamp.substr(6, 2);
            j.add("Archived homepage", date, "https://web.archive.org/web/" + stamp + "/" + original,
                  {.provider = "Internet Archive", .query = j.target, .basis = "Archive capture",
                   .scope = "Homepage captures", .source_origin = original, .source_date = date});
            ++captured;
        }
        coverage(j, "Internet Archive", "Homepage captures", captured ? CoverageState::Complete : CoverageState::Empty);
    } catch (const std::exception& e) {
        coverage(j, "Internet Archive", "Homepage captures", CoverageState::Unavailable);
        j.log(e.what());
    }
}
}  // namespace

const std::vector<Module>& domain_modules() {
    static const std::vector<Module> modules = {
        {"Domain DNS", "Public DNS, mail records and related host/IP pivots", Domain, domain_dns},
        {"Domain RDAP", "Public registry, registrar, status and dates", Domain, domain_rdap},
        {"Certificate history", "Names from publicly logged certificates", Domain, domain_certificates},
        {"Domain archive", "Dated public homepage captures", Domain, domain_archive},
    };
    return modules;
}
