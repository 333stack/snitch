// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#pragma once
#include <iosfwd>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "osint.h"

const std::vector<Module>& ip_modules();
const std::vector<Module>& email_modules();
const std::vector<Module>& username_modules();
const std::vector<Module>& phone_modules();
const std::vector<Module>& dork_modules();
const std::vector<Module>& domain_modules();
const std::vector<Module>& music_modules();
const std::vector<Module>& social_modules();

// Pure parts, exposed for tests.
std::string mail_provider(const std::vector<std::string>& mx);
std::string discord_username(std::string_view input);  // lowercase handle, empty when Discord would reject it
bool plausible_discord_token(std::string_view token);
bool profile_marker_matches(long expected_status, std::string_view marker, long status, std::string_view body);

struct SearchResult {
    std::string url, title, snippet;
    std::vector<std::string> engines;
    std::string source_origin, source_date;
};
std::vector<SearchResult> parse_searxng(const std::string& body, std::vector<std::string>* failed_engines);
std::vector<SearchResult> parse_ddg(const std::string& html);
std::vector<SearchResult> parse_bing(const std::string& html);
std::string fill(std::string tmpl, const std::vector<std::pair<std::string, std::string>>& vars);  // "{key}" -> value

struct PublicPhoneProfile {
    std::string service, handle;
};
PublicPhoneProfile public_phone_profile(const SearchResult& result, const PhoneInfo& phone);

std::string carrier_for_prefix(std::istream& records, std::string_view digits, std::string* dataset = nullptr);

inline constexpr char auto_dork_section[] = "Auto dorking";
struct GeneratedSearch {
    std::string label, query;
};
std::vector<GeneratedSearch> auto_dork_queries(Type type, std::string_view target, const PhoneInfo& phone);
bool auto_dork_hit(Type type, std::string_view target, const PhoneInfo& phone, const SearchResult& result);
bool text_matches_phone(const std::string& text, const PhoneInfo& target);

std::vector<std::string> read_search_proxies(std::istream& config);

std::vector<std::string> domain_dns_answers(const nlohmann::json& response, int record_type);
std::vector<Finding> domain_certificate_hits(const nlohmann::json& response, std::string_view target);

struct SpotifyCredit {
    std::string role, name, source;
};
std::vector<SpotifyCredit> musicbrainz_recording_credits(const nlohmann::json& recording);
std::vector<std::string> musicbrainz_linked_recordings(const nlohmann::json& metadata, std::string_view track);
std::string spotify_public_artist(std::string_view html, std::string_view title);
std::string musicbrainz_title_artist_match(const nlohmann::json& search, std::string_view title, std::string_view artist);
std::string spotify_username_result(const SearchResult& result, std::string_view target);
std::string soundcloud_embed_title(const nlohmann::json& metadata, std::string_view profile);

struct SocialProfile {
    std::string platform, url;
};
std::vector<SocialProfile> social_profile_urls(std::string_view input);
bool potential_social_account(const SocialProfile& profile, std::string_view effective_url,
                              long status, std::string_view body);

const nlohmann::json& bundled_username_catalog();
