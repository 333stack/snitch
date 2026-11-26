// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

enum Type : unsigned { Phone = 1, Email = 2, Ip = 4, Username = 8, Domain = 16, SpotifyTrack = 32 };
Type detect(std::string_view target);  // 0 when it looks like none of them
const char* type_name(Type t);
std::string normalize_domain(std::string_view input);
std::string normalize_username(std::string_view input);
std::string spotify_track_url(std::string_view input);

struct Evidence {
    std::string provider, query, basis;
    std::int64_t observed_at = 0;  // Unix seconds
    int review = 0;  // index into evidence_reviews
    std::string note{};
    std::string scope{}, source_origin{}, source_date{}, excerpt{};
};

inline constexpr const char* evidence_reviews[] = {"Unreviewed", "Reviewed", "Dismissed"};

struct Finding {
    std::string module, key, value, url;
    bool pivot = false;  // value is itself a target worth investigating
    std::size_t run_id = 0;
    Evidence evidence;
    Type pivot_type = Type(0);
};

// Copied into every job at launch, so workers never read UI-owned state.
struct Settings {
    std::string searxng = "http://127.0.0.1:8888";
    std::string region = "US";  // phone numbers without a leading + are parsed as this country
    bool all_engines = false;
    bool full_profile_catalog = true;
    std::string discord_token;  // from keys.json; never written to settings.json
};

enum class CoverageState { Complete, Empty, Blocked, Unavailable, Skipped };

struct Coverage {
    std::string provider, scope;
    CoverageState state;
    bool exhaustive = false;
};

struct Job {
    std::string target;
    Type type;
    Settings settings;
    std::stop_token stop;
    std::function<void(Finding)> emit;     // the runner fills in Finding::module
    std::function<void(std::string)> log;
    std::function<void(Coverage)> coverage;

    void add(std::string key, std::string value, std::string url = "", Evidence evidence = {}) const {
        emit({{}, std::move(key), std::move(value), std::move(url), false, 0, std::move(evidence)});
    }
    void pivot(std::string key, std::string value, std::string url = "", Evidence evidence = {}, Type type = Type(0)) const {
        emit({{}, std::move(key), std::move(value), std::move(url), true, 0, std::move(evidence), type});
    }
};

struct Module {
    const char* name;
    const char* help;
    unsigned types;          // Type bits this module accepts
    void (*run)(const Job&); // runs on a worker thread; throw std::exception to report failure
};

const std::vector<Module>& modules();

// Shared helpers used by more than one module (util.cpp).
std::string data_path(const std::string& file);           // MARK47_DATA env, else <source>/data
std::string read_file(const std::string& path);           // throws when unreadable
std::vector<std::string> doh(const std::string& name, const std::string& rrtype, std::stop_token stop);  // DNS over HTTPS answers
std::string html_text(std::string_view html);             // strip tags, decode common entities, collapse spaces
std::vector<std::string> find_emails(std::string_view s);
std::vector<std::string> find_phones(std::string_view s); // loose: 10-15 digit runs with common separators

struct PhoneInfo {
    bool ok = false;
    std::string e164, international, national, digits, region, country, type, location;
    bool valid = false;
};
PhoneInfo phone_info(const std::string& number, const std::string& default_region);
