// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include "findings.h"

#include <algorithm>
#include <set>
#include <stdexcept>

namespace {
std::vector<std::vector<std::string>> csv_rows(std::string_view csv) {
    if (csv.starts_with("\xef\xbb\xbf")) csv.remove_prefix(3);
    std::vector<std::vector<std::string>> rows;
    std::vector<std::string> row;
    std::string field;
    bool quoted = false, closed = false;
    for (std::size_t i = 0; i < csv.size(); ++i) {
        const char ch = csv[i];
        if (quoted) {
            if (ch != '"') field += ch;
            else if (i + 1 < csv.size() && csv[i + 1] == '"') { field += '"'; ++i; }
            else { quoted = false; closed = true; }
        } else if (ch == ',' || ch == '\r' || ch == '\n') {
            row.push_back(std::move(field));
            field.clear();
            closed = false;
            if (ch != ',') {
                if (ch == '\r' && i + 1 < csv.size() && csv[i + 1] == '\n') ++i;
                rows.push_back(std::move(row));
                row.clear();
            }
        } else if (ch == '"' && field.empty() && !closed) {
            quoted = true;
        } else if (closed || ch == '"') {
            throw std::runtime_error("Malformed WhatsMyName CSV");
        } else {
            field += ch;
        }
    }
    if (quoted) throw std::runtime_error("Unterminated quoted CSV field");
    if (!field.empty() || !row.empty() || closed) {
        row.push_back(std::move(field));
        rows.push_back(std::move(row));
    }
    return rows;
}

std::string lower(std::string value) {
    for (auto& ch : value) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    return value;
}

bool profile_url(std::string_view url) {
    const unsigned scheme = url.starts_with("https://") ? 8 : url.starts_with("http://") ? 7 : 0;
    if (!scheme || std::ranges::any_of(url, [](unsigned char ch) {
        return ch <= 32 || ch == 127 || ch == '\\' || ch == '<' || ch == '>';
    })) return false;
    const auto host = url.substr(scheme, url.find_first_of("/?#", scheme) - scheme);
    return !host.empty() && host.find('@') == host.npos;
}
}  // namespace

std::vector<Finding> import_whatsmyname_csv(std::string_view csv, std::string_view target, std::size_t run_id) {
    if (csv.size() > 1024 * 1024) throw std::runtime_error("WhatsMyName CSV exceeds 1 MiB");
    const auto rows = csv_rows(csv);
    constexpr auto absent = std::string_view::npos;
    std::size_t header = 0, site = absent, link = absent, category = absent, username = absent, status = absent;
    for (; header < rows.size(); ++header) {
        site = link = category = username = status = absent;
        for (std::size_t i = 0; i < rows[header].size(); ++i) {
            const auto label = lower(finding_text(rows[header][i]));
            if (label == "site" || label == "platform" || label == "website") site = i;
            if (label == "link" || label == "url" || label == "profile url") link = i;
            if (label == "category") category = i;
            if (label == "username" || label == "handle") username = i;
            if (label == "status" || label == "result") status = i;
        }
        if (site != absent && link != absent) break;
    }
    if (header == rows.size()) throw std::runtime_error("WhatsMyName CSV needs Site and Link columns");

    std::vector<Finding> findings;
    std::set<std::pair<std::string, std::string>> seen;
    for (std::size_t i = header + 1; i < rows.size(); ++i) {
        const auto& row = rows[i];
        auto field = [&](std::size_t column) { return column < row.size() ? finding_text(row[column]) : ""; };
        const auto name = field(site), url = field(link);
        if (name.empty() || !profile_url(url)) continue;
        if (status != absent) {
            const auto result = lower(field(status));
            if (result != "found" && result != "account found" && result != "true" && result != "yes") continue;
        }
        const auto submitted = field(username);
        if (!submitted.empty() && lower(normalize_username(submitted)) != lower(normalize_username(target)))
            throw std::runtime_error("CSV username differs from the selected run");
        if (!seen.emplace(name, url).second) continue;
        findings.push_back({whatsmyname_csv_section, "Potential account · " + name, std::string(target), url, false, run_id,
                            {.provider = "WhatsMyName.app", .query = std::string(target),
                             .basis = "Imported WhatsMyName CSV hit", .scope = field(category)}});
    }
    return findings;
}
