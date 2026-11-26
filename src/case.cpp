// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include "case.h"

#include <algorithm>
#include <map>
#include <optional>
#include <sstream>
#include <set>
#include <tuple>
#include <stdexcept>

#include "findings.h"

using json = nlohmann::json;

namespace {
Type case_type(const std::string& name) {
    for (Type type : {Phone, Email, Ip, Username, Domain, SpotifyTrack})
        if (name == type_name(type)) return type;
    throw std::runtime_error("unrecognized run target type");
}

std::size_t id(const json& value) {
    if (!value.is_number_integer() || (!value.is_number_unsigned() && value.get<std::int64_t>() < 0))
        throw std::runtime_error("invalid case reference");
    return value.get<std::size_t>();
}

std::string markdown_text(std::string_view input) {
    std::string out;
    for (char ch : finding_text(input)) {
        if (std::string_view("\\`*_{}[]<>()#+!|~.").find(ch) != std::string_view::npos) out += '\\';
        out += ch;
    }
    return out;
}

std::optional<std::string> source_url(std::string_view url) {
    const auto scheme = url.starts_with("https://") ? 8U : url.starts_with("http://") ? 7U : 0U;
    if (!scheme || std::ranges::any_of(url, [](unsigned char ch) {
        return ch <= 32 || ch == 127 || ch == '<' || ch == '>' || ch == '\\';
    })) return std::nullopt;
    const auto host = url.substr(scheme, url.find_first_of("/?#", scheme) - scheme);
    if (host.empty() || host.find_first_of("@%") != host.npos) return std::nullopt;
    return std::string(url);
}
}  // namespace

const char* coverage_name(CoverageState state) {
    switch (state) {
        case CoverageState::Complete: return "Complete";
        case CoverageState::Empty: return "Empty";
        case CoverageState::Blocked: return "Blocked";
        case CoverageState::Unavailable: return "Unavailable";
        case CoverageState::Skipped: return "Skipped";
    }
    return "Unknown";
}

static CoverageState coverage_state(std::string_view name) {
    for (auto state : {CoverageState::Complete, CoverageState::Empty, CoverageState::Blocked,
                       CoverageState::Unavailable, CoverageState::Skipped})
        if (name == coverage_name(state)) return state;
    throw std::runtime_error("invalid case coverage state");
}

json case_json(const CaseData& data) {
    json out = {{"format", "mark47-case"}, {"version", 1}, {"runs", json::array()},
                {"evidence", json::array()}, {"log", data.log}};
    for (const auto& run : data.runs) {
        auto coverage = json::array();
        for (const auto& check : run.coverage)
            coverage.push_back({{"provider", check.provider}, {"scope", check.scope},
                                {"state", coverage_name(check.state)}, {"exhaustive", check.exhaustive}});
        out["runs"].push_back({{"target", run.target}, {"type", type_name(run.type)},
                               {"parent_run", run.parent}, {"parent_evidence", run.parent_evidence},
                               {"errors", run.errors}, {"outcome", run.outcome}, {"coverage", std::move(coverage)}});
    }
    for (std::size_t i = 0; i < data.findings.size(); ++i) {
        const auto& f = data.findings[i];
        const auto& e = f.evidence;
        out["evidence"].push_back({{"id", i + 1}, {"module", f.module}, {"key", f.key},
                                   {"value", f.value}, {"url", f.url}, {"pivot", f.pivot},
                                   {"run", f.run_id}, {"provider", e.provider}, {"query", e.query},
                                   {"basis", e.basis}, {"observed_at", e.observed_at},
                                   {"review", e.review}, {"note", e.note}, {"scope", e.scope},
                                   {"source_origin", e.source_origin}, {"source_date", e.source_date}, {"excerpt", e.excerpt},
                                   {"pivot_type", f.pivot_type ? type_name(f.pivot_type) : ""}});
    }
    return out;
}

CaseData parse_case(const json& data) {
    if (data.value("format", "") != "mark47-case" || data.value("version", 0) != 1)
        throw std::runtime_error("unsupported case format");
    const auto& runs = data.at("runs");
    const auto& evidence = data.at("evidence");
    if (!runs.is_array() || !evidence.is_array()) throw std::runtime_error("invalid case records");
    CaseData result;
    result.log = data.at("log").get<std::vector<std::string>>();
    for (const auto& j : runs) {
        Run run{j.at("target").get<std::string>(), case_type(j.at("type").get<std::string>()),
                id(j.at("parent_run")), id(j.at("errors")), j.at("outcome").get<std::string>(),
                id(j.at("parent_evidence"))};
        if (run.parent > result.runs.size() || (!!run.parent != !!run.parent_evidence))
            throw std::runtime_error("invalid pivot ancestry");
        const auto checks = j.value("coverage", json::array());
        if (!checks.is_array()) throw std::runtime_error("invalid case coverage");
        for (const auto& c : checks)
            run.coverage.push_back({c.at("provider"), c.at("scope"),
                                    coverage_state(c.at("state").get<std::string>()),
                                    c.value("exhaustive", false)});
        if (run.outcome == "running") run.outcome = "interrupted";
        result.runs.push_back(std::move(run));
    }
    for (const auto& j : evidence) {
        if (id(j.at("id")) != result.findings.size() + 1)
            throw std::runtime_error("invalid evidence sequence");
        Finding f{j.at("module"), j.at("key"), j.at("value"), j.at("url"),
                  j.at("pivot"), id(j.at("run"))};
        auto& e = f.evidence;
        e = {j.at("provider"), j.at("query"), j.at("basis"), j.at("observed_at"), j.at("review"), j.at("note")};
        e.scope = j.value("scope", "");
        e.source_origin = j.value("source_origin", "");
        e.source_date = j.value("source_date", "");
        e.excerpt = j.value("excerpt", "");
        if (f.module == "WhatsMyName fallback") f.module = whatsmyname_fallback_name;  // label before 2026-11-25
        else if (f.module == "WhatsMyName") {
            if (e.basis == "Imported WhatsMyName CSV hit") f.module = whatsmyname_csv_section;
            else if (e.basis == "Navigation link") f.module = whatsmyname_fallback_name;
            else if (e.basis == "Bundled public profile rule matched" || e.basis == "Public profile URL responded")
                f.module = "Social profiles";
        }
        const auto pivot_type = j.value("pivot_type", "");
        if (!pivot_type.empty()) {
            if (!f.pivot) throw std::runtime_error("pivot type requires pivot evidence");
            f.pivot_type = case_type(pivot_type);
        }
        if (!f.run_id || f.run_id > result.runs.size() || e.review < 0 || e.review >= int(std::size(evidence_reviews)))
            throw std::runtime_error("invalid evidence record");
        result.findings.push_back(std::move(f));
    }
    for (const auto& run : result.runs) {
        if (!run.parent_evidence) continue;
        if (run.parent_evidence > result.findings.size()) throw std::runtime_error("missing pivot evidence");
        const auto& parent = result.findings[run.parent_evidence - 1];
        if (parent.run_id != run.parent || !parent.pivot) throw std::runtime_error("invalid pivot evidence");
    }
    return result;
}

std::string case_report(const CaseData& data) {
    std::ostringstream report;
    report << "# Investigation report\n";
    report << "\n## Timeline\n\n";
    for (std::size_t i = 0; i < data.runs.size(); ++i) {
        const auto& run = data.runs[i];
        report << "- Run " << i + 1 << " (" << type_name(run.type) << ')';
        report << " · " << markdown_text(run.target) << " · " << markdown_text(run.outcome);
        if (run.parent_evidence) report << " · pivot from evidence E" << run.parent_evidence;
        const auto blocked = std::ranges::count(run.coverage, CoverageState::Blocked, &Coverage::state);
        const auto unavailable = std::ranges::count(run.coverage, CoverageState::Unavailable, &Coverage::state);
        if (!run.coverage.empty()) report << " · " << blocked << " blocked, " << unavailable << " unavailable checks";
        report << '\n';
    }
    std::map<std::string, std::size_t> citations;
    std::vector<std::string> sources;
    report << "\n## Evidence\n\n";
    for (std::size_t i = 0; i < data.findings.size(); ++i) {
        const auto& f = data.findings[i];
        const auto& e = f.evidence;
        report << "- **E" << i + 1 << "** · Run " << f.run_id << " · " << evidence_reviews[e.review];
        report << " · " << markdown_text(f.module) << " / " << markdown_text(f.key) << ": " << markdown_text(f.value);
        if (!e.provider.empty()) report << " · Provider: " << markdown_text(e.provider);
        if (!e.basis.empty()) report << " · Basis: " << markdown_text(e.basis);
        if (e.observed_at) report << " · Observed (Unix UTC): " << e.observed_at;
        if (!e.query.empty()) report << " · Query: " << markdown_text(e.query);
        if (!e.excerpt.empty() && f.value.find(e.excerpt) == f.value.npos)
            report << " · Excerpt: " << markdown_text(e.excerpt);
        if (!e.source_date.empty()) report << " · Source date: " << markdown_text(e.source_date);
        if (auto origin = source_url(e.source_origin)) report << " · Origin: <" << *origin << ">";
        if (!e.note.empty()) report << " · Note: " << markdown_text(e.note);
        if (auto url = e.basis == "Navigation link" ? std::nullopt : source_url(f.url)) {
            const auto [it, inserted] = citations.try_emplace(url->substr(0, url->find('#')), sources.size() + 1);
            if (inserted) sources.push_back(std::move(*url));
            report << " · Source " << it->second;
        }
        report << '\n';
    }
    report << "\n## Sources (" << sources.size() << " distinct URLs)\n\n";
    for (std::size_t i = 0; i < sources.size(); ++i)
        report << "- Source " << i + 1 << ": <" << sources[i] << ">\n";
    return report.str();
}

namespace {
bool complete_scope(const Run& run, const Evidence& e) {
    if (e.scope.empty()) return false;
    bool complete = false;
    for (const auto& item : run.coverage) {
        if (item.provider != e.provider || item.scope != e.scope) continue;
        if (!item.exhaustive || (item.state != CoverageState::Complete && item.state != CoverageState::Empty))
            return false;
        complete = true;
    }
    return complete;
}

std::string stable_source(std::string_view input) {
    const auto url = source_url(input);
    if (!url) return {};
    std::string key = url->substr(0, url->find('#'));
    const auto begin = key.find("://") + 3;
    const auto end = key.find_first_of("/?", begin);
    for (std::size_t i = begin; i < std::min(key.size(), end); ++i) {
        if (key[i] >= 'A' && key[i] <= 'Z') key[i] += 'a' - 'A';
    }
    return key;
}
}  // namespace

std::vector<CaseChange> compare_runs(const CaseData& data, std::size_t before, std::size_t after) {
    if (!before || after <= before || after > data.runs.size()) return {};
    const auto& older = data.runs[before - 1];
    const auto& newer = data.runs[after - 1];
    if (older.type != newer.type || older.target != newer.target) return {};

    using Key = std::tuple<std::string_view, std::string_view, std::string_view, std::string_view, bool>;
    struct Cohort { std::vector<std::size_t> removed, added; };
    std::map<Key, Cohort> fields;
    for (std::size_t i = 0; i < data.findings.size(); ++i) {
        const auto& f = data.findings[i];
        if (f.run_id != before && f.run_id != after) continue;
        auto& field = fields[{f.module, f.key, f.evidence.provider, f.evidence.scope, f.pivot}];
        (f.run_id == before ? field.removed : field.added).push_back(i + 1);
    }
    const auto finding = [&](std::size_t id) -> const Finding& { return data.findings[id - 1]; };
    std::vector<CaseChange> result;
    for (auto& [key, field] : fields) {
        const auto same_value = [&](std::size_t left, std::size_t right) {
            return std::tie(finding(left).value, finding(left).evidence.source_date) ==
                   std::tie(finding(right).value, finding(right).evidence.source_date);
        };
        auto unique = [&](std::vector<std::size_t>& ids) {
            std::ranges::stable_sort(ids, [&](auto left, auto right) {
                return std::tie(finding(left).value, finding(left).evidence.source_date) <
                       std::tie(finding(right).value, finding(right).evidence.source_date);
            });
            ids.erase(std::unique(ids.begin(), ids.end(), same_value), ids.end());
        };
        unique(field.removed);
        unique(field.added);
        const auto previous_size = field.removed.size();
        const auto current_size = field.added.size();
        for (auto& old_id : field.removed) {
            const auto match = std::ranges::find_if(field.added, [&](auto new_id) {
                return new_id && same_value(old_id, new_id);
            });
            if (match == field.added.end()) continue;
            result.push_back({"Seen again", old_id, *match});
            old_id = 0;
            *match = 0;
        }
        std::erase(field.removed, 0U);
        std::erase(field.added, 0U);
        if (field.removed.empty() && field.added.empty()) continue;
        const auto& witness = finding(field.removed.empty() ? field.added.front() : field.removed.front()).evidence;
        const bool comparable = complete_scope(older, witness) && complete_scope(newer, witness);
        if (comparable && previous_size == 1 && current_size == 1) {
            result.push_back({"Changed", field.removed.front(), field.added.front()});
            continue;
        }
        for (const auto id : field.removed) result.push_back({comparable ? "Absent in recheck" : "Unknown coverage", id, 0});
        for (const auto id : field.added) result.push_back({comparable ? "New" : "First observed", 0, id});
    }
    return result;
}

std::vector<SourceMatch> compare_sources(const CaseData& data, std::size_t evidence_id) {
    if (!evidence_id || evidence_id > data.findings.size()) return {};
    const auto& f = data.findings[evidence_id - 1];
    const auto url = stable_source(f.url);
    if (url.empty() || f.evidence.basis == "Navigation link") return {};
    const auto origin = stable_source(f.evidence.source_origin);
    const auto text = finding_text(f.evidence.excerpt.empty() ? f.value : f.evidence.excerpt);
    std::vector<SourceMatch> matches;
    for (std::size_t i = 0; i < data.findings.size(); ++i) {
        const auto& candidate = data.findings[i];
        if (i + 1 == evidence_id || candidate.evidence.basis == "Navigation link") continue;
        const auto other = stable_source(candidate.url);
        if (other.empty()) continue;
        const auto other_origin = stable_source(candidate.evidence.source_origin);
        if (other == url) matches.push_back({i + 1, "Same URL"});
        else if ((!origin.empty() && (origin == other || origin == other_origin)) || other_origin == url)
            matches.push_back({i + 1, "Shared recorded origin"});
        else if (text.size() >= 80 && text == finding_text(candidate.evidence.excerpt.empty() ? candidate.value : candidate.evidence.excerpt))
            matches.push_back({i + 1, "Matching text · origin unconfirmed"});
    }
    return matches;
}

PhoneReview phone_summary(const CaseData& data, std::size_t run_id) {
    if (!run_id || run_id > data.runs.size() || data.runs[run_id - 1].type != Phone) return {};
    PhoneReview result;
    std::map<std::size_t, std::string_view> numbers;
    std::map<std::string_view, std::set<std::string_view>> profiles, facts;
    for (std::size_t i = 0; i < data.findings.size(); ++i) {
        const auto& f = data.findings[i];
        if (f.module == "Number info" && f.key == "E.164") numbers[f.run_id] = f.value;
        if (f.run_id != run_id) continue;
        if (f.module == "Number info" || f.key.starts_with("Public match · ")) result.entries.push_back(i + 1);
        if (f.key.starts_with("Public match · ")) profiles[f.key].insert(f.value);
    }
    for (const auto& [service, handles] : profiles)
        if (handles.size() > 1)
            result.conflicts.push_back("Multiple profile handles on " + std::string(service.substr(std::string_view("Public match · ").size())));
    const auto current = numbers.find(run_id);
    if (current == numbers.end()) return result;
    for (const auto& f : data.findings) {
        const auto candidate = numbers.find(f.run_id);
        if (f.module != "Number info" || candidate == numbers.end() || candidate->second != current->second) continue;
        if (f.key == "line type" || (f.key == "original carrier" && f.value != "No matching prefix" &&
                                    !f.value.starts_with("Carrier data unavailable")))
            facts[f.key].insert(f.value);
    }
    for (const auto& [field, values] : facts)
        if (values.size() > 1) result.conflicts.push_back("Different " + std::string(field) + " observations across runs");
    return result;
}
