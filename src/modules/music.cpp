// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include "modules.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>

#include "findings.h"
#include "http.h"

using json = nlohmann::json;

namespace {
bool ascii_alnum(unsigned char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
}

std::string ascii_lower(std::string_view input) {
    std::string result(input);
    for (auto& ch : result) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    return result;
}

std::string_view spotify_path(std::string_view url) {
    constexpr std::string_view host = "https://open.spotify.com/";
    if (!url.starts_with(host)) return {};
    url.remove_prefix(host.size());
    url = url.substr(0, url.find_first_of("?#"));
    if (url.ends_with('/')) url.remove_suffix(1);
    if (url.starts_with("intl-")) {
        const auto slash = url.find('/');
        if (slash == url.npos) return {};
        url.remove_prefix(slash + 1);
    }
    return url;
}

bool musicbrainz_id(std::string_view id) {
    if (id.size() != 36) return false;
    for (std::size_t i = 0; i < id.size(); ++i) {
        const auto ch = static_cast<unsigned char>(id[i]);
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (ch != '-') return false; }
        else if (!std::isxdigit(ch)) return false;
    }
    return true;
}

bool blocked(const Response& r) {
    return r.status == 403 || r.status == 429 || r.status == 503 || r.retry_after;
}

std::string lucene_phrase(std::string_view value) {
    std::string phrase = "\"";
    for (char ch : value) {
        if (ch == '"' || ch == '\\') phrase += '\\';
        phrase += ch;
    }
    return phrase + '"';
}

void soundcloud(const Job& j) {
    if (j.target.empty() || !std::ranges::all_of(j.target, [](unsigned char ch) {
        return ascii_alnum(ch) || ch == '-' || ch == '_';
    })) {
        j.log("handle is not a SoundCloud profile slug");
        if (j.coverage) j.coverage({"SoundCloud oEmbed", "User profile", CoverageState::Skipped});
        return;
    }
    const auto profile = "https://soundcloud.com/" + url_encode(j.target);
    const auto embed = "https://soundcloud.com/oembed?format=json&url=" + url_encode(profile);
    const auto r = http_get(embed, j.stop);
    if (j.stop.stop_requested()) return;
    if (r.status != 200) {
        const auto state = r.status == 404 ? CoverageState::Empty :
                           r.status == 403 || r.status == 429 || r.retry_after ? CoverageState::Blocked : CoverageState::Unavailable;
        if (j.coverage) j.coverage({"SoundCloud oEmbed", "User profile", state});
        if (r.status == 404) return;
        throw std::runtime_error(r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    }
    const auto title = soundcloud_embed_title(json::parse(r.body), profile);
    if (title.empty()) throw std::runtime_error("SoundCloud did not return a matching profile embed");
    j.add("Potential account · SoundCloud", j.target, profile,
          {.provider = "SoundCloud oEmbed", .query = j.target, .basis = "Public profile response", .scope = "User profile", .excerpt = title});
    if (j.coverage) j.coverage({"SoundCloud oEmbed", "User profile", CoverageState::Complete});
}

void spotify_track(const Job& j) {
    const auto track = spotify_track_url(j.target);
    if (track.empty()) throw std::runtime_error("invalid Spotify track URL");
    j.add("Open Spotify track", track, track, {.provider = "Spotify", .basis = "Navigation link"});
    const auto embed = http_get("https://open.spotify.com/oembed?url=" + url_encode(track), j.stop);
    if (j.stop.stop_requested()) return;
    std::string title;
    if (embed.status == 200) {
        try {
            title = finding_text(json::parse(embed.body).value("title", ""));
            if (!title.empty()) j.add("Track title", title, track,
                                     {.provider = "Spotify oEmbed", .query = track, .basis = "Public track metadata"});
        } catch (const json::exception& e) {
            j.log(std::string("Spotify oEmbed: malformed reply (") + e.what() + ")");
        }
    }

    constexpr std::string_view scope = "Track credits";
    auto status = [&](CoverageState state, std::string message) {
        if (j.coverage) j.coverage({"MusicBrainz", std::string(scope), state});
        j.emit({"Spotify credits", "Lookup status", std::move(message), "", false, 0,
                {.provider = "MusicBrainz", .query = track, .basis = "Provider lookup status", .scope = std::string(scope)}});
    };

    constexpr std::string_view mb = "https://musicbrainz.org/ws/2/";
    const Request request{.headers = {"User-Agent: snitch/1.0 (local music metadata lookup)"},
                          .min_interval_s = 1.1, .cache = false};
    const auto linked = http_get(std::string(mb) + "url?resource=" + url_encode(track) +
                                 "&inc=recording-rels&fmt=json", j.stop, request);
    if (j.stop.stop_requested()) return;
    if (linked.status != 200 && linked.status != 404) {
        status(blocked(linked) ? CoverageState::Blocked : CoverageState::Unavailable,
               blocked(linked) ? "MusicBrainz rate-limited or blocked the lookup" : "MusicBrainz link lookup unavailable");
        return;
    }

    std::string id;
    std::string basis = "MusicBrainz recording linked to exact Spotify track URL";
    try {
        const auto ids = linked.status == 200 ? musicbrainz_linked_recordings(json::parse(linked.body), track)
                                             : std::vector<std::string>{};
        if (ids.size() > 1) { status(CoverageState::Empty, "Multiple MusicBrainz recordings link to this track"); return; }
        if (!ids.empty()) id = ids.front();
        else {
            if (blocked(embed) || title.empty() || title.size() > 250) {
                status(blocked(embed) ? CoverageState::Blocked : CoverageState::Unavailable,
                       "No exact recording link and Spotify track metadata is unavailable");
                return;
            }
            const auto page = http_get(track, j.stop, {.headers = {"Accept-Language: en"}, .cache = false});
            if (j.stop.stop_requested()) return;
            if (page.status != 200) {
                status(blocked(page) ? CoverageState::Blocked : CoverageState::Unavailable,
                       "No exact recording link and Spotify artist metadata is unavailable");
                return;
            }
            const auto artist = spotify_public_artist(page.body, title);
            if (!artist.empty()) {
                const auto search = http_get(std::string(mb) + "recording?fmt=json&limit=50&query=" +
                    url_encode("recording:" + lucene_phrase(title) + " AND artist:" + lucene_phrase(artist)), j.stop, request);
                if (j.stop.stop_requested()) return;
                if (search.status != 200) {
                    status(blocked(search) ? CoverageState::Blocked : CoverageState::Unavailable, "MusicBrainz recording search unavailable");
                    return;
                }
                id = musicbrainz_title_artist_match(json::parse(search.body), title, artist);
                basis = "Unique exact public title and artist match · review";
            }
        }
        if (id.empty()) {
            status(CoverageState::Empty, "No unambiguous recording match in the available metadata");
            return;
        }
        const auto recording = http_get(std::string(mb) + "recording/" + id +
            "?inc=artist-rels+work-rels+work-level-rels&fmt=json", j.stop, request);
        if (j.stop.stop_requested()) return;
        if (recording.status != 200) {
            status(blocked(recording) ? CoverageState::Blocked : CoverageState::Unavailable, "MusicBrainz recording credits unavailable");
            return;
        }
        const auto data = json::parse(recording.body);
        if (data.value("id", "") != id) throw std::runtime_error("MusicBrainz returned a different recording ID");
        const auto credits = musicbrainz_recording_credits(data);
        if (credits.empty()) {
            status(CoverageState::Empty, "Matched recording has no supported contributor credits");
            return;
        }
        for (const auto& credit : credits)
            j.emit({"Spotify credits", credit.role, credit.name, credit.source, false, 0,
                    {.provider = "MusicBrainz", .query = track, .basis = basis, .scope = std::string(scope)}});
        if (j.coverage) j.coverage({"MusicBrainz", std::string(scope), CoverageState::Complete});
    } catch (const std::exception& e) {
        j.log(e.what());
        status(CoverageState::Unavailable, "MusicBrainz metadata could not be processed");
    }
}
}  // namespace

std::string spotify_track_url(std::string_view input) {
    std::string_view id;
    if (input.starts_with("spotify:track:")) id = input.substr(14);
    else {
        const auto path = spotify_path(input);
        if (!path.starts_with("track/")) return {};
        id = path.substr(6);
    }
    if (id.size() != 22 || !std::ranges::all_of(id, ascii_alnum)) return {};
    return "https://open.spotify.com/track/" + std::string(id);
}

std::string spotify_username_result(const SearchResult& result, std::string_view target) {
    const auto path = spotify_path(result.url);
    const auto slash = path.find('/');
    if (slash == path.npos) return {};
    const auto id = path.substr(slash + 1);
    if (id.empty() || id.find('/') != id.npos) return {};
    const auto kind = path.substr(0, slash);
    if (kind == "user" && id == target) return "Indexed Spotify user ID";
    if (kind == "artist" && id.size() == 22 && std::ranges::all_of(id, ascii_alnum) &&
        auto_dork_hit(Username, target, {}, result)) return "Spotify artist lead";
    if (kind == "track" && !spotify_track_url(result.url).empty() &&
        auto_dork_hit(Username, target, {}, result)) return "Spotify track lead";
    return {};
}

std::string soundcloud_embed_title(const json& metadata, std::string_view profile) {
    if (metadata.value("provider_name", "") != "SoundCloud" || metadata.value("type", "") != "rich") return {};
    const auto html = metadata.value("html", "");
    const auto author = metadata.value("author_url", "");
    if (!author.empty() && author != profile && author != std::string(profile) + "/") return {};
    // The official endpoint returns an embeddable player, not a generic HTTP-200 page.
    if (html.find("https://w.soundcloud.com/player/") == html.npos) return {};
    return finding_text(metadata.value("title", ""));
}

std::vector<std::string> musicbrainz_linked_recordings(const json& metadata, std::string_view track) {
    std::vector<std::string> ids;
    if (spotify_track_url(metadata.value("resource", "")) != track) return ids;
    for (const auto& rel : metadata.value("relations", json::array())) {
        if (rel.value("target-type", "") != "recording" || !rel.contains("recording")) continue;
        auto id = rel.at("recording").value("id", "");
        if (musicbrainz_id(id) && std::ranges::find(ids, id) == ids.end()) ids.push_back(std::move(id));
    }
    return ids;
}

std::string spotify_public_artist(std::string_view html, std::string_view title) {
    const auto begin = html.find("<title>");
    if (begin == html.npos) return {};
    const auto end = html.find("</title>", begin + 7);
    if (end == html.npos || end - begin > 600) return {};
    auto text = html_text(html.substr(begin + 7, end - begin - 7));
    const auto prefix = std::string(title) + " - Song, Lyrics, and Music Video by ";
    constexpr std::string_view suffix = " | Spotify";
    if (!text.starts_with(prefix) || !text.ends_with(suffix) || text.size() <= prefix.size() + suffix.size()) return {};
    auto artist = finding_text(std::string_view(text).substr(prefix.size(), text.size() - prefix.size() - suffix.size()));
    return artist.size() <= 180 ? artist : "";
}

std::string musicbrainz_title_artist_match(const json& search, std::string_view title, std::string_view artist) {
    const auto& rows = search.at("recordings");
    if (!rows.is_array() || search.at("count").get<std::size_t>() > rows.size()) return {};
    const auto normalized_title = ascii_lower(finding_text(title)), normalized_artist = ascii_lower(finding_text(artist));
    if (normalized_title.empty() || normalized_artist.empty()) return {};
    std::set<std::string> matches;
    for (const auto& row : rows) {
        const auto id = row.value("id", "");
        if (!musicbrainz_id(id) || ascii_lower(finding_text(row.value("title", ""))) != normalized_title) continue;
        const auto artists = row.value("artist-credit", json::array());
        if (artists.size() != 1) continue;
        const auto& credit = artists[0];
        const auto named = ascii_lower(finding_text(credit.value("name", "")));
        const auto credited = ascii_lower(finding_text(credit.value("artist", json::object()).value("name", "")));
        if (named == normalized_artist || credited == normalized_artist) matches.insert(id);
    }
    return matches.size() == 1 ? *matches.begin() : "";
}

std::vector<SpotifyCredit> musicbrainz_recording_credits(const json& recording) {
    const auto id = recording.value("id", "");
    if (!musicbrainz_id(id)) throw std::runtime_error("invalid MusicBrainz recording ID");
    const auto source = "https://musicbrainz.org/recording/" + id;
    static const std::map<std::string_view, std::string_view> roles{
        {"writer", "Songwriter"}, {"composer", "Composer"}, {"lyricist", "Lyricist"},
        {"librettist", "Librettist"}, {"producer", "Producer"}, {"executive producer", "Executive producer"},
        {"engineer", "Engineer"}, {"recording", "Recording engineer"}, {"mix", "Mixing engineer"},
        {"mastering", "Mastering engineer"}, {"arranger", "Arranger"},
        {"instrument", "Instrument performer"}, {"vocal", "Vocal performer"}, {"performer", "Performer"}
    };
    std::vector<SpotifyCredit> credits;
    std::set<std::tuple<std::string, std::string, std::string>> seen;
    auto add = [&](std::string role, std::string name, const std::string& url) {
        name = finding_text(name);
        if (credits.size() < 100 && !name.empty() && name.size() <= 180 && seen.emplace(role, ascii_lower(name), url).second)
            credits.push_back({std::move(role), std::move(name), url});
    };
    auto relationships = [&](const json& entity, const std::string& url) {
        for (const auto& rel : entity.value("relations", json::array())) {
            if (rel.value("target-type", "") != "artist" || !rel.contains("artist")) continue;
            const auto type = rel.value("type", "");
            const auto role = roles.find(type);
            if (role == roles.end()) continue;
            auto name = rel.value("target-credit", "");
            if (name.empty()) name = rel.at("artist").value("name", "");
            add(std::string(role->second), std::move(name), url);
        }
    };
    relationships(recording, source);
    for (const auto& rel : recording.value("relations", json::array())) {
        if (rel.value("type", "") != "performance" || rel.value("target-type", "") != "work" || !rel.contains("work")) continue;
        const auto& work = rel.at("work");
        const auto work_id = work.value("id", "");
        if (musicbrainz_id(work_id)) relationships(work, "https://musicbrainz.org/work/" + work_id);
    }
    return credits;
}

const std::vector<Module>& music_modules() {
    static const std::vector<Module> modules = {
        {"SoundCloud", "Check public SoundCloud username via oEmbed", Username, soundcloud},
        {"Spotify track", "Automatically look up publicly cataloged track and songwriting credits", SpotifyTrack, spotify_track},
    };
    return modules;
}
