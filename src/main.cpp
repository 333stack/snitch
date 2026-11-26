// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <system_error>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <optional>
#include <cstdio>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "case.h"
#include "findings.h"
#include "kit/app.h"
#include "modules.h"
#include "nlohmann/json.hpp"
#include "osint.h"

using json = nlohmann::json;

// Shared between the UI thread and module workers; guard every access with m.
struct Store {
    std::mutex m;
    CaseData data;
    int running = 0;
};

static std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t"), e = s.find_last_not_of(" \t");
    return b == std::string::npos ? "" : s.substr(b, e - b + 1);
}

static void fitted_text(kit::Context& c, const std::string& text, float width, kit::Color color = 0) {
    if (width <= 0) return;
    if (c.font->width(text) <= width) { kit::text(c, text, color); return; }
    constexpr std::string_view ellipsis = "...";
    width -= c.font->width(ellipsis);
    if (width <= 0) return;
    std::size_t first = 0, last = text.size();
    while (first < last) {
        const auto mid = first + (last - first + 1) / 2;
        if (c.font->width(std::string_view(text).substr(0, mid)) <= width) first = mid;
        else last = mid - 1;
    }
    // The width search works in bytes. Back up if the boundary splits a UTF-8 character.
    while (first && first < text.size() && (static_cast<unsigned char>(text[first]) & 0xc0) == 0x80) --first;
    kit::text(c, text.substr(0, first) + "...", color);
    c.behave(c.id(text), c.last_item(), false);
    if (c.font->width(text) + c.px(12) <= c.viewport().x) kit::tooltip(c, text);
}

static std::string utc_time(std::int64_t stamp, const char* format) {
    if (!stamp) return {};
    const std::time_t time = stamp;
    std::tm utc{};
    char display[32] = {};
    if (!gmtime_r(&time, &utc) || !std::strftime(display, sizeof display, format, &utc)) return {};
    return display;
}

static std::string finding_label(const Finding& f) {
    std::string label = finding_text(f.key);
    if (f.module == "Lookup links" && label.starts_with("open: ")) label.erase(0, 6);
    if (label == "created_at") return "Created";
    if (label == "twitter_username") return "Twitter username";
    if (!label.empty() && label.front() >= 'a' && label.front() <= 'z')
        label.front() -= 'a' - 'A';
    return label;
}

static void open_url(const std::string& url) {
    if (!url.starts_with("http://") && !url.starts_with("https://")) return;  // URLs come from scraped pages
    pid_t pid;
    char* argv[] = {(char*)"xdg-open", (char*)url.c_str(), nullptr};
    if (posix_spawnp(&pid, "xdg-open", nullptr, nullptr, argv, environ) == 0)
        std::thread([pid] { waitpid(pid, nullptr, 0); }).detach();  // reap; no shell involved
}

static std::filesystem::path settings_file() {
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    const char* home = std::getenv("HOME");
    return std::filesystem::path(xdg && *xdg ? xdg : std::string(home ? home : ".") + "/.config") / "mark47" / "settings.json";
}

// Credentials stay out of settings.json; write_file stages with mkstemp, so the file is owner-only.
static std::filesystem::path keys_file() { return settings_file().parent_path() / "keys.json"; }


// Stage in the destination directory so publication is atomic on the same filesystem.
static void write_file(const std::filesystem::path& path, std::string_view content, bool replace) {
    std::string temp = (path.parent_path() / ".mark47-XXXXXX").string();
    const int fd = mkstemp(temp.data());
    if (fd == -1) throw std::system_error(errno, std::generic_category(), "create temporary file");
    int error = 0;
    for (size_t offset = 0; offset < content.size();) {
        const auto written = write(fd, content.data() + offset, content.size() - offset);
        if (written > 0) offset += written;
        else if (written == 0 || errno != EINTR) { error = written == 0 ? EIO : errno; break; }
    }
    if (!error && fsync(fd) == -1) error = errno;
    if (close(fd) == -1 && !error) error = errno;
    if (!error && (replace ? rename(temp.c_str(), path.c_str()) : link(temp.c_str(), path.c_str())) == -1)
        error = errno;
    unlink(temp.c_str());
    if (error) throw std::system_error(error, std::generic_category(), path.string());
}

static std::filesystem::path write_snapshot(std::string_view prefix, std::string_view extension,
                                            std::string_view content) {
    const auto stamp = std::chrono::system_clock::now().time_since_epoch();
    const auto stem = std::string(prefix) + std::to_string(stamp.count());
    for (std::size_t attempt = 0;; ++attempt) {
        const auto path = std::filesystem::current_path() /
                          (stem + "_" + std::to_string(attempt) + std::string(extension));
        try {
            write_file(path, content, false);
            return path;
        } catch (const std::system_error& e) {
            if (e.code() != std::errc::file_exists) throw;
        }
    }
}

static std::string read_bounded_file(const std::filesystem::path& path, std::streamoff limit) {
    if (!std::filesystem::is_regular_file(path)) throw std::runtime_error("path is not a regular file");
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("cannot open the file");
    const auto bytes = stream.tellg();
    if (bytes <= 0 || bytes > limit) throw std::runtime_error("file is empty or exceeds the size limit");
    std::string content(static_cast<std::size_t>(bytes), '\0');
    stream.seekg(0);
    if (!stream.read(content.data(), static_cast<std::streamsize>(content.size())))
        throw std::runtime_error("cannot read file contents");
    return content;
}

static CaseData open_case_file(const std::filesystem::path& path) {
    return parse_case(json::parse(read_bounded_file(path, 64 * 1024 * 1024)));
}

int main(int argc, char** argv) {
    Settings settings;
    bool use_whatsmyname_fallback = true;
    std::map<std::string, bool> enabled;  // module name -> on; missing = on
    try {
        const json s = json::parse(read_file(settings_file()));
        settings.searxng = s.value("searxng", settings.searxng);
        settings.region = s.value("region", settings.region);
        settings.all_engines = s.value("all_engines", false);
        use_whatsmyname_fallback = s.value("whatsmyname_fallback", true);
        for (const auto& n : s.value("disabled", json::array())) enabled[n] = false;
        const auto legacy_catalog = enabled.find("WhatsMyName");
        settings.full_profile_catalog = s.value("full_profile_catalog", legacy_catalog == enabled.end());
        if (legacy_catalog != enabled.end()) enabled.erase(legacy_catalog);
    } catch (const std::exception&) {}  // first run or unreadable: defaults

    Store store;
    std::stop_source stop;
    std::vector<std::jthread> workers;  // declared after store: joined before it is destroyed
    std::string target = argc > 1 ? argv[1] : "", filter;
    int type_pick = 0;  // 0 = auto
    bool hide_weak = true;
    size_t log_seen = 0;
    size_t parent_evidence = 0;
    std::optional<std::size_t> selected_evidence;
    std::size_t whatsmyname_import_run = 0;
    std::string whatsmyname_csv_path, whatsmyname_import_status;
    bool comparing = false;
    int comparison_before = 0, comparison_after = 0;
    int phone_run = 0;
    bool settings_open = false;
    std::string discord_token, discord_token_input, settings_status;
    try {
        discord_token = json::parse(read_file(keys_file())).value("discord_token", "");
    } catch (const std::exception&) {}  // no keys saved yet
    settings.discord_token = discord_token;
    auto store_discord_token = [&](std::string token) {
        try {
            if (token.empty()) {
                std::filesystem::remove(keys_file());
            } else {
                std::filesystem::create_directories(keys_file().parent_path());
                write_file(keys_file(), json{{"discord_token", token}}.dump(2), true);
            }
            discord_token = std::move(token);
            settings.discord_token = discord_token;
            discord_token_input.clear();
            settings_status = discord_token.empty() ? "Token removed" : "Token saved";
        } catch (const std::exception& e) {
            settings_status = std::string("Save failed: ") + e.what();
        }
    };
    std::string case_path, pending_case_path;
    bool case_dirty = false;
    std::string pivot_target;
    std::vector<FindingGroup> finding_groups;
    std::size_t grouped_count = 0;
    bool grouped_hide_weak = hide_weak;
    std::string grouped_filter;
    std::set<std::size_t> expanded_findings;
    static const char* type_items[] = {"Auto", "Phone", "Email", "IP", "Username", "Domain", "Track"};
    static const Type type_of_pick[] = {Type(0), Phone, Email, Ip, Username, Domain, SpotifyTrack};
    const auto pick_for = [](Type type) {
        const auto it = std::ranges::find(type_of_pick, type);
        return it == std::end(type_of_pick) ? 0 : int(it - std::begin(type_of_pick));
    };

    auto launch = [&](std::string t, Type type) {  // caller holds store.m
        const auto pivot = t == pivot_target ? parent_evidence : 0;
        if (type == Username) {
            t = normalize_username(t);
            if (t.empty()) { store.data.log.push_back("Enter a valid username."); return; }
        }
        if (type == Domain) {
            t = normalize_domain(t);
            if (t.empty()) { store.data.log.push_back("Enter a domain or a homepage URL with no path."); return; }
        }
        if (type == SpotifyTrack) {
            t = spotify_track_url(t);
            if (t.empty()) { store.data.log.push_back("Enter an open.spotify.com track URL."); return; }
        }
        workers.clear();  // all finished (running == 0): joins instantly
        stop = {};
        const size_t parent = pivot;
        parent_evidence = 0;
        case_dirty = true;
        pending_case_path.clear();
        store.data.runs.push_back({t, type, parent ? store.data.findings[parent - 1].run_id : 0,
                                   0, "running", parent, {}});
        const size_t run_id = store.data.runs.size();
        store.data.log.push_back("run " + std::string(type_name(type)) + " " + t);
        const bool fallback = type == Username && use_whatsmyname_fallback;
        if (fallback) {
            if (auto link = whatsmyname_fallback(t, run_id)) {
                link->evidence.observed_at = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                store.data.findings.push_back(std::move(*link));
            }
        }
        for (const Module& mod : modules()) {
            if (!(mod.types & type)) continue;
            if (!enabled.try_emplace(mod.name, true).first->second) {
                store.data.runs.back().coverage.push_back({mod.name, "Module", CoverageState::Skipped});
                continue;
            }
            Job job{t, type, settings, stop.get_token(), {}, {}, {}};
            job.emit = [&store, &mod, run_id](Finding f) {
                if (f.module.empty()) f.module = mod.name;
                f.run_id = run_id;
                auto& e = f.evidence;
                if (e.provider.empty()) e.provider = mod.name;
                if (e.basis.empty()) e.basis = f.module == "Lookup links" ? "Navigation link" : "Module observation";
                e.observed_at = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                { std::lock_guard l(store.m); store.data.findings.push_back(std::move(f)); }
                kit::wake();
            };
            job.coverage = [&store, run_id](Coverage status) {
                { std::lock_guard l(store.m); store.data.runs[run_id - 1].coverage.push_back(std::move(status)); }
                kit::wake();
            };
            job.log = [&store, &mod](std::string s) {
                { std::lock_guard l(store.m); store.data.log.push_back(std::string(mod.name) + ": " + s); }
                kit::wake();
            };
            try {
                workers.emplace_back([&store, &mod, run_id, job = std::move(job)] {
                    std::string status;
                    try { mod.run(job); } catch (const std::exception& e) { status = std::string("error: ") + e.what(); }
                    {
                        std::lock_guard l(store.m);
                        const bool stopped = job.stop.stop_requested();
                        auto& run = store.data.runs[run_id - 1];
                        if (!status.empty()) ++run.errors;
                        if (!stopped) run.coverage.push_back({mod.name, "Module",
                            status.empty() ? CoverageState::Complete : CoverageState::Unavailable});
                        if (--store.running == 0)
                            run.outcome = stopped ? "stopped" : run.errors ? "completed_with_errors" : "completed";
                        if (stopped && status.empty()) status = "stopped";
                        if (!status.empty()) store.data.log.push_back(std::string(mod.name) + ": " + status);
                    }
                    kit::wake();
                });
                ++store.running;
            } catch (const std::system_error& e) {
                ++store.data.runs.back().errors;
                store.data.log.push_back(std::string(mod.name) + ": " + e.what());
            }
        }
        if (!store.running) {
            auto& run = store.data.runs.back();
            run.outcome = run.errors ? "failed" : fallback ? "completed" : "no_modules";
        }
    };

    auto export_json = [&] {  // caller holds store.m
        json out = {{"schema_version", 2}, {"target", store.data.runs.back().target},
                    {"runs", json::array()}, {"findings", json::array()}, {"log", store.data.log}};
        for (size_t i = 0; i < store.data.runs.size(); ++i) {
            const auto& run = store.data.runs[i];
            out["runs"].push_back({{"id", i + 1}, {"target", run.target}, {"type", type_name(run.type)},
                                   {"outcome", run.outcome}, {"errors", run.errors},
                                   {"parent_run_id", run.parent ? json(run.parent) : json(nullptr)}});
        }
        for (const auto& f : store.data.findings)
            out["findings"].push_back({{"module", f.module}, {"key", f.key}, {"value", f.value}, {"url", f.url},
                                       {"run_id", f.run_id}, {"pivot", f.pivot}});
        try {
            const auto path = write_snapshot("mark47_", ".json", out.dump(2, ' ', false, json::error_handler_t::replace));
            store.data.log.push_back("exported " + path.string());
        } catch (const std::exception& e) {
            store.data.log.push_back(std::string("export failed: ") + e.what());
        }
    };

    auto reset_view = [&] {
        selected_evidence.reset();
        whatsmyname_import_run = 0;
        whatsmyname_csv_path.clear();
        whatsmyname_import_status.clear();
        comparing = false;
        phone_run = 0;
        settings_open = false;
        expanded_findings.clear();
        finding_groups.clear();
        grouped_count = std::size_t(-1);
        parent_evidence = 0;
        pivot_target.clear();
        pending_case_path.clear();
        log_seen = 0;
    };

    auto save_case = [&] {
        try {
            const auto content = case_json(store.data).dump(2, ' ', false, json::error_handler_t::replace);
            if (content.size() > 64 * 1024 * 1024) throw std::runtime_error("case exceeds 64 MiB");
            const auto path = write_snapshot("mark47_case_", ".case.json", content);
            case_path = path.string();
            pending_case_path.clear();
            case_dirty = false;
            store.data.log.push_back("case saved " + case_path);
        } catch (const std::exception& e) {
            store.data.log.push_back(std::string("case save failed: ") + e.what());
        }
    };

    auto open_case = [&] {
        const std::string path = trim(case_path);
        if (path.empty()) return;
        if (case_dirty && pending_case_path != path) {
            pending_case_path = path;
            store.data.log.push_back("Unsaved case changes. Save a snapshot or confirm open to replace the workspace.");
            return;
        }
        try {
            auto data = open_case_file(path);
            store.data = std::move(data);
            reset_view();
            case_dirty = false;
            target = store.data.runs.empty() ? "" : store.data.runs.back().target;
            type_pick = store.data.runs.empty() ? 0 : pick_for(store.data.runs.back().type);
            filter.clear();
            store.data.log.push_back("case opened " + path);
        } catch (const std::exception& e) {
            pending_case_path.clear();
            store.data.log.push_back(std::string("open case failed: ") + e.what());
        }
    };

    auto export_report = [&] {
        try {
            const auto path = write_snapshot("mark47_report_", ".md", case_report(store.data));
            store.data.log.push_back("report exported " + path.string());
        } catch (const std::exception& e) {
            store.data.log.push_back(std::string("report export failed: ") + e.what());
        }
    };

    auto import_whatsmyname = [&] {
        const auto run_id = whatsmyname_import_run;
        try {
            const auto csv = read_bounded_file(trim(whatsmyname_csv_path), 1024 * 1024);
            auto hits = import_whatsmyname_csv(csv, store.data.runs[run_id - 1].target, run_id);
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            std::size_t added = 0;
            for (auto& hit : hits) {
                const bool duplicate = std::ranges::any_of(store.data.findings, [&](const Finding& f) {
                    return f.run_id == run_id && f.module == whatsmyname_csv_section && f.key == hit.key &&
                           f.url == hit.url && f.evidence.basis == hit.evidence.basis;
                });
                if (duplicate) continue;
                hit.evidence.observed_at = now;
                store.data.findings.push_back(std::move(hit));
                ++added;
            }
            whatsmyname_import_status = "Imported " + std::to_string(added) + " new WhatsMyName hits.";
            if (added) {
                case_dirty = true;
                pending_case_path.clear();
                store.data.log.push_back(whatsmyname_import_status + " Run " + std::to_string(run_id));
            }
        } catch (const std::exception& e) {
            whatsmyname_import_status = e.what();
        }
    };

    const int rc = kit::run("snitch", [&](kit::Context& c) {
        std::lock_guard l(store.m);
        const std::string t = trim(target);
        const auto detected = detect(t);
        const Type type = detected == SpotifyTrack ? SpotifyTrack : type_pick ? type_of_pick[type_pick] : detected;

        // Top bar
        const float row_w = c.avail().w;
        const bool wide = row_w >= 640;  // narrow (tiled) windows: buttons go on a second row
        kit::input_text(c, "Target", target, c.avail().w - (wide ? 360 : 150));
        c.same_line();
        kit::combo(c, "##type", type_pick, type_items, int(std::size(type_items)), 80);
        c.same_line();
        kit::text(c, t.empty() ? "" : type ? type_name(type) : "unknown type", type ? c.theme.accent : c.theme.danger);
        if (wide) c.same_line_at(row_w - 200);
        if (store.running) { if (kit::button(c, "Stop", 60)) stop.request_stop(); }
        else if (kit::button(c, "Run", 60) && type && !t.empty()) launch(t, type);
        c.same_line();
        if (kit::button(c, "Export", 60) && !store.data.findings.empty()) export_json();
        c.same_line();
        if (kit::button(c, "Clear", 0) && !store.running) {
            store.data = {};
            case_dirty = false;
            reset_view();
        }
        c.alloc(0, c.px(4));
        const bool case_wide = c.avail().w >= c.px(660);
        if (kit::input_text(c, "Case file", case_path, case_wide ? c.avail().w - c.px(400) : c.avail().w))
            pending_case_path.clear();
        if (case_wide) c.same_line();
        if (!store.running) {
            if (kit::button(c, pending_case_path.empty() ? "Open case" : "Confirm open")) open_case();
            c.same_line();
            if (kit::button(c, "Save case") && !store.data.runs.empty()) save_case();
            c.same_line();
            if (kit::button(c, "Report") && !store.data.runs.empty()) export_report();
            c.same_line();
            if (kit::button(c, "Settings")) {
                settings_open = true;
                comparing = false;
                phone_run = 0;
                whatsmyname_import_run = 0;
                selected_evidence.reset();
                settings_status.clear();
            }
            if (store.data.runs.size() >= 2) {
                c.same_line();
                if (kit::button(c, "Compare")) {
                    comparing = true;
                    settings_open = false;
                    whatsmyname_import_run = 0;
                    selected_evidence.reset();
                    phone_run = 0;
                    comparison_after = int(store.data.runs.size()) - 1;
                    comparison_before = comparison_after - 1;
                    std::map<std::pair<Type, std::string_view>, int> previous;
                    for (int i = 0; i < int(store.data.runs.size()); ++i) {
                        const auto& run = store.data.runs[i];
                        const auto key = std::pair<Type, std::string_view>{run.type, run.target};
                        const auto [it, inserted] = previous.try_emplace(key, i);
                        if (!inserted) {
                            comparison_before = it->second;
                            comparison_after = i;
                            it->second = i;
                        }
                    }
                }
            }
            const auto latest_phone = std::ranges::find_if(store.data.runs.rbegin(), store.data.runs.rend(),
                [](const Run& run) { return run.type == Phone; });
            if (latest_phone != store.data.runs.rend()) {
                c.same_line();
                if (kit::button(c, "Phone summary")) {
                    phone_run = int(latest_phone.base() - store.data.runs.begin());
                    settings_open = false;
                    whatsmyname_import_run = 0;
                    comparing = false;
                    selected_evidence.reset();
                }
            }
        } else {
            kit::text(c, "Stop or wait to manage case files", c.theme.text_dim);
        }
        c.alloc(0, 5);

        // Left column: modules + settings
        kit::begin_child(c, "##left", std::min(220.f, c.avail().w * 0.35f), 0, 0);
        kit::begin_child(c, "Modules", 0, c.avail().h - 132, kit::ChildBorder | kit::ChildScroll);
        if (!type) kit::text(c, "Enter a target (or pick its type)", c.theme.text_dim);
        for (size_t i = 0; i < modules().size(); i++) {
            const Module& m = modules()[i];
            if (!(m.types & type)) continue;
            c.push_id(int(i));
            bool& on = enabled.try_emplace(m.name, true).first->second;
            kit::checkbox(c, m.name, on);
            kit::tooltip(c, m.help);
            c.pop_id();
        }
        if (type == Username) {
            kit::checkbox(c, whatsmyname_fallback_name, use_whatsmyname_fallback);
            kit::tooltip(c, "Add a link to run the same username search on WhatsMyName.app");
        }
        kit::end_child(c);
        c.alloc(0, 5);
        kit::begin_child(c, "Settings", 0, 0);
        c.label_w = 52;
        kit::checkbox(c, "Dorks: use all search engines", settings.all_engines);
        kit::tooltip(c, "Adds Google, Bing, Yahoo, Yandex, Presearch, Baidu. More results, more blocking.");
        kit::checkbox(c, "Full profile catalog", settings.full_profile_catalog);
        kit::tooltip(c, "Use the bundled catalog with Social profiles");
        kit::input_text(c, "SearXNG", settings.searxng);
        kit::input_text(c, "Region", settings.region);
        kit::tooltip(c, "Country (ISO code, e.g. US, GB) for phone numbers typed without +");
        c.label_w = 0;
        kit::end_child(c);
        kit::end_child(c);
        c.same_line();

        // Right column: findings + log
        kit::begin_child(c, "##main", 0, 0, 0);
        kit::input_text(c, "Filter", filter, c.avail().w - c.px(90));
        c.same_line();
        kit::checkbox(c, "Hide weak", hide_weak);
        kit::tooltip(c, "Dork results that don't mention the target");
        c.alloc(0, 5);
        const char* panel = settings_open ? "Settings" :
                            whatsmyname_import_run ? "Import WhatsMyName" : selected_evidence ? "Evidence" :
                            comparing ? "Run comparison" :
                            phone_run ? "Phone summary" : "Findings";
        kit::begin_child(c, panel, 0, c.avail().h - 130,
                         kit::ChildBorder | kit::ChildScroll);
        c.alloc(0, 4);  // clear the group-box title
        if (grouped_count != store.data.findings.size() || grouped_filter != filter || grouped_hide_weak != hide_weak) {
            finding_groups = group_findings(store.data.findings, filter, hide_weak);
            grouped_count = store.data.findings.size();
            grouped_filter = filter;
            grouped_hide_weak = hide_weak;
        }

        auto evidence_button = [&](std::size_t id, std::string label) {
            if (!id || id > store.data.findings.size()) return;
            c.push_id(label);
            if (kit::button(c, "E" + std::to_string(id))) selected_evidence = id - 1;
            c.same_line();
            fitted_text(c, label, c.avail().w, c.theme.text_dim);
            c.pop_id();
        };

        if (settings_open) {
            if (kit::button(c, "Back")) settings_open = false;
            c.alloc(0, c.px(6));
            kit::text(c, "Discord user token (optional)", c.theme.accent);
            kit::text(c, discord_token.empty() ? "Not set" : "Saved, ending in " + discord_token.substr(discord_token.size() - 4),
                      c.theme.text_dim);
            kit::input_text(c, "Token", discord_token_input, c.avail().w);
            if (kit::button(c, "Save token")) {
                const auto token = trim(discord_token_input);
                if (plausible_discord_token(token)) store_discord_token(token);
                else settings_status = "That does not look like a Discord token";
            }
            if (!discord_token.empty()) {
                c.same_line();
                if (kit::button(c, "Remove token")) store_discord_token("");
            }
            if (!settings_status.empty()) fitted_text(c, settings_status, c.avail().w, c.theme.text_dim);
            c.alloc(0, c.px(6));
            fitted_text(c, "Stored owner-only in " + keys_file().string() + ". The field shows what you type until you save.",
                        c.avail().w, c.theme.text_dim);
            fitted_text(c, "Automating a user account breaks Discord's terms and can get that account banned.",
                        c.avail().w, c.theme.danger);
        } else if (whatsmyname_import_run) {
            const auto& run = store.data.runs[whatsmyname_import_run - 1];
            if (kit::button(c, "Back")) {
                whatsmyname_import_run = 0;
            } else {
                c.same_line();
                fitted_text(c, run.target, c.avail().w, c.theme.accent);
                kit::input_text(c, "CSV file", whatsmyname_csv_path, c.avail().w);
                if (kit::button(c, "Import CSV")) import_whatsmyname();
                if (!whatsmyname_import_status.empty())
                    fitted_text(c, whatsmyname_import_status, c.avail().w, c.theme.text_dim);
            }
        } else if (selected_evidence) {
            auto& f = store.data.findings[*selected_evidence];
            auto& e = f.evidence;
            if (kit::button(c, "Back")) selected_evidence.reset();
            c.same_line();
            kit::text(c, "Evidence E" + std::to_string(&f - store.data.findings.data() + 1) +
                         " · Run " + std::to_string(f.run_id), c.theme.accent);
            c.alloc(0, c.px(6));
            auto detail = [&](std::string label, const std::string& value) {
                if (value.empty()) return;
                const float width = c.avail().w;
                c.push_id(label);
                if (kit::button(c, "Copy") && c.set_clipboard) c.set_clipboard(value);
                c.same_line();
                fitted_text(c, label + " · " + finding_text(value), width - c.px(60));
                c.pop_id();
            };
            detail("Finding", f.key + ": " + f.value);
            detail("Source URL", f.url);
            detail("Recorded origin", e.source_origin);
            detail("Source date", e.source_date);
            if (!e.excerpt.empty() && f.value.find(e.excerpt) == f.value.npos) detail("Source excerpt", e.excerpt);
            detail("Provider", e.provider);
            detail("Search query", e.query);
            detail("Match basis", e.basis);
            detail("Observed", utc_time(e.observed_at, "%Y-%m-%d %H:%M:%S UTC"));
            c.alloc(0, c.px(6));
            const bool review_changed = kit::combo(c, "Review", e.review, evidence_reviews,
                                                   int(std::size(evidence_reviews)), c.px(160));
            const bool note_changed = kit::input_text(c, "Note", e.note, c.avail().w);
            if (review_changed || note_changed) {
                case_dirty = true;
                pending_case_path.clear();
            }

            const auto sources = compare_sources(store.data, static_cast<std::size_t>(&f - store.data.findings.data()) + 1);
            if (!sources.empty()) {
                c.alloc(0, c.px(6));
                kit::text(c, "Related sources", c.theme.accent);
                for (const auto& item : sources) {
                    const auto& source = store.data.findings[item.evidence_id - 1];
                    evidence_button(item.evidence_id, item.reason + " · " + source.url+
                        (source.evidence.source_date.empty() ? "" : " · " + source.evidence.source_date));
                }
            }
        } else if (comparing) {
            if (kit::button(c, "Back")) comparing = false;
            std::vector<std::string> labels;
            for (size_t i = 0; i < store.data.runs.size(); ++i)
                labels.push_back("Run " + std::to_string(i + 1) + " · " + store.data.runs[i].target);
            std::vector<const char*> items;
            for (const auto& label : labels) items.push_back(label.c_str());
            kit::combo(c, "Earlier", comparison_before, items.data(), int(items.size()), std::min(c.px(380), c.avail().w));
            kit::combo(c, "Later", comparison_after, items.data(), int(items.size()), std::min(c.px(380), c.avail().w));
            const auto& before = store.data.runs[comparison_before];
            const auto& after = store.data.runs[comparison_after];
            if (comparison_before >= comparison_after || before.target != after.target || before.type != after.type) {
                kit::text(c, "Choose two ordered runs for the same target.", c.theme.text_dim);
            } else {
                const auto changes = compare_runs(store.data, comparison_before + 1, comparison_after + 1);
                if (changes.empty()) kit::text(c, "No evidence to compare.", c.theme.text_dim);
                for (const auto& change : changes) {
                    const auto& f = store.data.findings[(change.after ? change.after : change.before) - 1];
                    c.push_id(int(change.after ? change.after : change.before));
                    if (change.before) {
                        if (kit::button(c, "E" + std::to_string(change.before))) selected_evidence = change.before - 1;
                        c.same_line();
                    }
                    if (change.after) {
                        if (kit::button(c, "E" + std::to_string(change.after))) selected_evidence = change.after - 1;
                        c.same_line();
                    }
                    const std::string value = change.state == "Changed" ?
                        finding_text(store.data.findings[change.before - 1].value) + " to " + finding_text(f.value) :
                        finding_text(f.value);
                    fitted_text(c, change.state + " · " + f.key + ": " + value, c.avail().w);
                    c.pop_id();
                }
                for (auto index : {comparison_before, comparison_after}) {
                    c.alloc(0, c.px(6));
                    const auto& checks = store.data.runs[index].coverage;
                    kit::text(c, "Coverage · Run " + std::to_string(index + 1), c.theme.accent);
                    if (checks.empty()) kit::text(c, "No coverage was recorded.", c.theme.text_dim);
                    for (const auto& result : checks)
                        fitted_text(c, std::string(coverage_name(result.state)) + " · " + result.provider +
                                       " · " + result.scope, c.avail().w, c.theme.text_dim);
                }
            }
        } else if (phone_run) {
            const auto run_id = static_cast<std::size_t>(phone_run);
            const auto& run = store.data.runs[run_id - 1];
            if (kit::button(c, "Back")) phone_run = 0;
            c.same_line();
            fitted_text(c, run.target + " · Run " + std::to_string(run_id), c.avail().w, c.theme.accent);
            kit::text(c, "Current carrier and account ownership: Unknown", c.theme.text_dim);
            const auto summary = phone_summary(store.data, run_id);
            if (summary.entries.empty()) kit::text(c, "No phone evidence was collected.", c.theme.text_dim);
            for (const auto id : summary.entries) {
                const auto& f = store.data.findings[id - 1];
                std::string label = f.key + " · " + finding_text(f.value);
                if (f.key.starts_with("Public match · ")) {
                    const auto date = f.evidence.source_date.empty() ?
                                      utc_time(f.evidence.observed_at, "Observed %Y-%m-%d UTC") : f.evidence.source_date;
                    if (!date.empty()) label += " · " + date;
                }
                evidence_button(id, std::move(label));
            }
            for (const auto& conflict : summary.conflicts) fitted_text(c, conflict, c.avail().w, c.theme.accent);
            std::size_t blocked = 0, unavailable = 0, checks = 0;
            for (const auto& item : run.coverage) {
                if (item.scope == "Module" || item.state == CoverageState::Skipped) continue;
                ++checks;
                if (item.state == CoverageState::Blocked) ++blocked;
                if (item.state == CoverageState::Unavailable) ++unavailable;
            }
            const std::string coverage = !checks ? "No search coverage recorded" : std::to_string(checks) +
                " search checks · " + std::to_string(blocked) + " blocked · " + std::to_string(unavailable) + " unavailable";
            fitted_text(c, coverage, c.avail().w, c.theme.text_dim);
        } else {
            auto row = [&](const Finding& fd, const std::string& label, const std::string& url,
                           const std::string& related, bool nested) {
                const float width = c.avail().w;
                const float gap = c.px(4);
                const float indent = nested ? c.px(16) : 0;
                const float height = c.font->line_h + c.px(3);
                const float copy_w = c.font->width("Copy") + c.px(10);
                const float open_w = url.empty() ? 0 : c.font->width("Open") + c.px(10);
                const float pivot_w = fd.pivot ? c.font->width("Pivot") + c.px(10) : 0;
                const float related_w = related.empty() ? 0 : c.font->width(related) + c.px(10);
                const float evidence_w = c.font->width("Details") + c.px(10);
                const float actions_w = evidence_w + gap + copy_w + gap + (open_w ? open_w + gap : 0) +
                                        (pivot_w ? pivot_w + gap : 0) + (related_w ? related_w + gap : 0);
                std::string value = finding_text(fd.value);
                if (value == fd.url && !url.empty()) {
                    const auto scheme = url.find("://");
                    value = scheme == url.npos ? url : url.substr(scheme + 3);
                }
                const float text_w = width - indent - actions_w;
                const bool compact = text_w < c.px(145);
                const float label_w = std::min(c.px(190), std::max(c.px(60), text_w * 0.36f));
                c.alloc(std::max(1.f, indent), height);
                c.same_line_at(indent);
                fitted_text(c, label, compact ? width - indent : label_w - gap, nested ? c.theme.text_dim : c.theme.text);
                if (!value.empty()) {
                    if (!compact) c.same_line_at(indent + label_w);
                    fitted_text(c, value, compact ? width : text_w - label_w - gap, c.theme.text_dim);
                }
                if (!compact) c.same_line_at(width - actions_w + gap);
                if (kit::button(c, "Copy", copy_w, height) && c.set_clipboard)
                    c.set_clipboard(fd.pivot || url.empty() ? fd.value : url);
                if (open_w) {
                    c.same_line(gap);
                    if (kit::button(c, "Open", open_w, height)) open_url(url);
                    kit::tooltip(c, url);
                }
                if (pivot_w) {
                    c.same_line(gap);
                    if (kit::button(c, "Pivot", pivot_w, height)) {
                        target = pivot_target = fd.value;
                        parent_evidence = static_cast<std::size_t>(&fd - store.data.findings.data()) + 1;
                        type_pick = pick_for(fd.pivot_type);
                    }
                    kit::tooltip(c, "Make this the target (then Run)");
                }
                c.same_line(gap);
                if (kit::button(c, "Details", evidence_w, height))
                    selected_evidence = static_cast<std::size_t>(&fd - store.data.findings.data());
                if (related.empty()) return false;
                c.same_line(gap);
                return kit::button(c, related, related_w, height);
            };

            std::size_t previous_run = 0;
            std::string_view previous_module;
            if (finding_groups.empty())
                kit::text(c, store.data.findings.empty() ? "No findings yet" : "No matching findings", c.theme.text_dim);
            for (const auto& group : finding_groups) {
                const auto& primary = store.data.findings[group.members.front()];
                if (previous_run != primary.run_id) {
                    if (previous_run) { c.alloc(0, c.px(4)); kit::separator(c); }
                    previous_run = primary.run_id;
                    previous_module = {};
                    const Run& run = store.data.runs[primary.run_id - 1];
                    const std::string heading = finding_text(run.target) + " (" + type_name(run.type) +
                                                ")  ·  Run " + std::to_string(previous_run);
                    const std::string pivot = run.parent_evidence ? "Via E" + std::to_string(run.parent_evidence) : "";
                    const auto reserve = (pivot.empty() ? 0.f : c.font->width(pivot) + c.px(24)) +
                                         (run.type == Phone ? c.font->width("Phone summary") + c.px(24) : 0.f) +
                                         (run.type == Username ? c.font->width("Import WMN CSV") + c.px(24) : 0.f);
                    fitted_text(c, heading, c.avail().w - reserve, c.theme.accent);
                    if (!pivot.empty()) {
                        c.same_line();
                        c.push_id(int(previous_run));
                        if (kit::button(c, pivot)) selected_evidence = run.parent_evidence - 1;
                        c.pop_id();
                    }
                    if (run.type == Phone) {
                        c.same_line();
                        c.push_id(int(previous_run));
                        if (kit::button(c, "Phone summary")) phone_run = int(previous_run);
                        c.pop_id();
                    }
                    if (run.type == Username) {
                        c.same_line();
                        c.push_id(int(previous_run));
                        if (kit::button(c, "Import WMN CSV")) {
                            whatsmyname_import_run = previous_run;
                            whatsmyname_import_status.clear();
                        }
                        c.pop_id();
                    }
                }
                if (previous_module != primary.module) {
                    c.alloc(0, c.px(3));
                    fitted_text(c, primary.module, c.avail().w, c.theme.accent);
                    previous_module = primary.module;
                }
                c.push_id(int(group.id));
                const bool has_related = group.members.size() > 1;
                bool expanded = expanded_findings.contains(group.id);
                const auto& url = has_related && !group.profile_url.empty() ? group.profile_url : primary.url;
                const std::string related = has_related ? (expanded ? "Hide" : "+" + std::to_string(group.members.size() - 1) + " related") : "";
                const std::string label = has_related && !group.profile_url.empty() && !primary.key.starts_with("Public match · ") &&
                                          !primary.key.starts_with("Potential hit · ") ?
                                          "GitHub profile" : finding_label(primary);
                if (row(primary, label, url, related, false)) {
                    if (expanded) expanded_findings.erase(group.id);
                    else expanded_findings.insert(group.id);
                    expanded = !expanded;
                }
                if (expanded && has_related) {
                    for (const auto i : group.members) {
                        const Finding& detail = store.data.findings[i];
                        if (i == group.members.front() && url == detail.url) continue;
                        c.push_id(int(i));
                        row(detail, detail.module + " / " + finding_label(detail), detail.url, "", true);
                        c.pop_id();
                    }
                }
                c.pop_id();
            }
        }
        kit::end_child(c);
        c.alloc(0, 5);
        kit::begin_child(c, "Log", 0, 0, kit::ChildBorder | kit::ChildScroll);
        c.alloc(0, 4);
        for (size_t i = 0; i < store.data.log.size(); i++) {
            c.push_id(int(i));
            kit::text(c, store.data.log[i], c.theme.text_dim);
            c.pop_id();
        }
        if (store.data.log.size() != log_seen) { log_seen = store.data.log.size(); if (log_seen) c.scroll_into_view(c.last_item()); }  // follow new lines
        kit::end_child(c);
        kit::end_child(c);
    }, {.w = 1280, .h = 760});

    stop.request_stop();  // workers observe cancellation through their stop tokens
    try {
        json s = {{"searxng", settings.searxng}, {"region", settings.region}, {"all_engines", settings.all_engines}, {"full_profile_catalog", settings.full_profile_catalog},
                  {"whatsmyname_fallback", use_whatsmyname_fallback}, {"disabled", json::array()}};
        for (auto& [name, on] : enabled) if (!on) s["disabled"].push_back(name);
        std::filesystem::create_directories(settings_file().parent_path());
        write_file(settings_file(), s.dump(2), true);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "snitch: settings save failed: %s\n", e.what());
    }
    return rc;
}
