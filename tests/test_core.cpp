// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#undef NDEBUG  // asserts are the test
#include <cassert>
#include <cstdio>
#include <sstream>

#include "case.h"
#include "findings.h"
#include "modules.h"

static bool has(const std::vector<std::string>& v, const std::string& s) { return std::find(v.begin(), v.end(), s) != v.end(); }

int main() {
    // Target detection
    assert(detect("8.8.8.8") == Ip);
    assert(detect("2001:4860:4860::8888") == Ip);
    assert(detect("john.doe+x@example.co.uk") == Email);
    assert(detect("+1 (555) 123-4567") == Phone);
    assert(detect("555.123.4567") == Phone);
    assert(detect("torvalds") == Username);
    assert(detect("@torvalds") == Username);
    assert(detect("john_doe-99") == Username);
    assert(detect("") == 0);
    assert(detect("two words") == Username);
    assert(detect("a@b") == Username || detect("a@b") == 0);  // no dot in domain: not an email
    assert(detect("999.1.1.1") != Ip);

    // Phone parsing (libphonenumber)
    PhoneInfo p = phone_info("+1 650-253-0000", "US");
    assert(p.ok && p.valid && p.e164 == "+16502530000" && p.region == "US" && p.country == "United States");
    assert(!p.location.empty());  // "Mountain View, CA"
    p = phone_info("020 7946 0018", "GB");
    assert(p.ok && p.e164 == "+442079460018" && p.region == "GB");
    assert(!phone_info("hello", "US").ok);

    // Entity extraction
    auto e = find_emails("Contact: John.Doe@Example.com, jane@mail.example.org. icon@2x.png x@y");
    assert(e.size() == 2 && has(e, "john.doe@example.com") && has(e, "jane@mail.example.org"));
    auto ph = find_phones("call (555) 123-4567 or +44 20 7946 0018; order 12345 on 2024-01-02");
    assert(has(ph, "(555) 123-4567") && has(ph, "+44 20 7946 0018") && ph.size() == 2);

    assert(html_text("<b>Linus</b> &amp; <i>Co</i>&#39;s  page") == "Linus & Co's page");
    assert(fill("\"{a}\" {b} {a}", {{"a", "x"}, {"b", "{a}"}}) == "\"x\" {a} x");  // values are not re-expanded

    assert(mail_provider({"aspmx.l.google.com"}) == "Google Workspace / Gmail");
    assert(mail_provider({"example-com.mail.protection.outlook.com"}) == "Microsoft 365 / Outlook");
    assert(mail_provider({}).empty());

    assert(profile_marker_matches(200, "profile-header", 200, "<div class=profile-header>"));
    assert(!profile_marker_matches(200, "profile-header", 200, "Not found"));
    assert(!profile_marker_matches(200, "profile-header", 404, "profile-header"));
    assert(!profile_marker_matches(0, "", 0, ""));
    const auto& bundled = bundled_username_catalog().at("sites");
    assert(bundled.size() == 691);
    int public_get = 0, unavailable = 0, disabled = 0;
    for (const auto& row : bundled) {
        const auto mode = row.at("mode").get<std::string>();
        assert(!row.contains("post_body"));
        if (mode == "unavailable") { ++unavailable; continue; }
        if (mode == "disabled") { ++disabled; continue; }
        assert(mode == "marker" || mode == "profile");
        assert(row.at("uri_check").get<std::string>().find("{account}") != std::string::npos);
        ++public_get;
    }
    assert(public_get == 686 && unavailable == 4 && disabled == 1);

    // Search result parsers (markup trimmed from real pages, Nov 2026)
    const std::string ddg = R"(<h2 class="result__title"><a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fgithub.com%2Ftorvalds&amp;rut=abc">torvalds (Linus Torvalds) &middot; GitHub</a></h2>
        <a class="result__snippet" href="//duckduckgo.com/l/?uddg=x">Linus <b>Torvalds</b> torvalds. Portland, OR</a>
        <a rel="nofollow" class="result__a" href="https://duckduckgo.com/y.js?ad=1">Ad</a>)";
    auto d = parse_ddg(ddg);
    assert(d.size() == 1 && d[0].url == "https://github.com/torvalds" && d[0].snippet == "Linus Torvalds torvalds. Portland, OR");

    const std::string bing = R"(<li class="b_algo" data-id><h2><a target="_blank" href="https://www.bing.com/ck/a?!&amp;&amp;p=1&amp;u=a1aHR0cHM6Ly9lbi53aWtpcGVkaWEub3JnL3dpa2kvTGludXNfVG9ydmFsZHM&amp;ntb=1"><strong>Linus Torvalds</strong> - Wikipedia</a></h2><p class="b_lineclamp2">Finnish software engineer</p></li>
        <li class="b_algo"><h2><a href="https://example.com/x?msockid=abc">Plain</a></h2></li>
        <li class="b_algo"><h2><a href="https://example.com/y?a=1&amp;msockid=abc&amp;b=2">Mid</a></h2></li>)";
    auto b = parse_bing(bing);
    assert(b.size() == 3 && b[2].url == "https://example.com/y?a=1&b=2" && b[0].url == "https://en.wikipedia.org/wiki/Linus_Torvalds" && b[0].title == "Linus Torvalds - Wikipedia");
    assert(b[0].snippet == "Finnish software engineer" && b[1].url == "https://example.com/x" && b[1].snippet.empty());

    std::vector<std::string> failed;
    auto s = parse_searxng(R"({"results":[{"url":"https://a.com","title":"A","content":"c","engines":["brave","duckduckgo"]}],
                               "unresponsive_engines":[["google","CAPTCHA"]]})", &failed);
    assert(s.size() == 1 && s[0].engines.size() == 2 && failed.size() == 1 && failed[0] == "google (CAPTCHA)");

    assert(parse_searxng(R"({"results":[]})", nullptr).empty());
    for (const char* malformed : {"<html>", "{}", R"({"results":null})"}) {
        bool rejected = false;
        try { parse_searxng(malformed, nullptr); }
        catch (const std::exception&) { rejected = true; }
        assert(rejected);
    }

    const auto carrier = [](std::string_view digits) {
        std::istringstream records("# fixture\n417|Carrier A\n4179|Carrier B\r\n"
                                   "41798|  \n417987|  Carrier C  \nmalformed\n");
        return carrier_for_prefix(records, digits);
    };
    assert(carrier("41798765432") == "Carrier C");
    assert(carrier("41798123456") == "Carrier B");
    assert(carrier("41761234567") == "Carrier A");
    assert(carrier("12025550101").empty());

    const auto phone = phone_info("+1 650 253 0000", "US");
    const auto profile = [&](std::string url, std::string snippet) {
        return public_phone_profile({std::move(url), "Public contact", std::move(snippet), {}}, phone);
    };
    auto linked = profile("https://www.instagram.com/fixture.name/", "Contact: (650) 253-0000.");
    assert(linked.service == "Instagram" && linked.handle == "fixture.name");
    linked = profile("https://bsky.app/profile/fixture.bsky.social", "Call +1 650 253 0000");
    assert(linked.service == "Bluesky" && linked.handle == "fixture.bsky.social");
    assert(profile("https://x.com/fixture", "650 views, 253 likes, 0000 comments").service.empty());
    assert(profile("https://x.com/fixture", "212-253-0000").service.empty());
    assert(profile("https://x.com/fixture/status/123", "Call 650-253-0000").service.empty());
    assert(profile("https://instagram.com.evil.test/fixture", "Call 650-253-0000").service.empty());
    assert(profile("https://instagram.com/accounts/", "Call 650-253-0000").service.empty());
    assert(profile("https://github.com/fixture/repo", "Call 650-253-0000").service.empty());

    const auto generated = auto_dork_queries(Phone, "650 253-0000", phone);
    assert(generated.size() == 2 && generated[0].query.starts_with("\"+16502530000\""));
    assert(auto_dork_queries(Email, "person@example.test", {}).size() == 2);
    assert(auto_dork_queries(Email, "bad\"@example.test", {}).empty());
    assert(auto_dork_queries(Username, "1234567", {}).size() == 2);
    assert(auto_dork_queries(Ip, "192.0.2.4", {}).size() == 2);
    assert(auto_dork_queries(Ip, "not-an-ip", {}).empty());
    const SearchResult hit{"https://example.test/profile", "Alice, portfolio", "Contact: (650) 253-0000", {}};
    assert(auto_dork_hit(Username, "alice", {}, hit));
    assert(!auto_dork_hit(Username, "ali", {}, hit));
    assert(auto_dork_hit(Phone, "6502530000", phone, hit));
    assert(!auto_dork_hit(Phone, "2122530000", phone_info("+12122530000", "US"), hit));
    assert(!auto_dork_hit(Username, "alice", {}, {"file:///alice", "Alice", "", {}}));
    assert(auto_dork_hit(Ip, "192.0.2.4", {}, {"https://example.test/a", "Operator for 192.0.2.4.", "", {}}));
    assert(!auto_dork_hit(Ip, "192.0.2.4", {}, {"https://example.test/a", "Operator for 192.0.2.44", "", {}}));
    auto sections = group_findings({
        {auto_dork_section, "Potential hit · Public profile", "Alice", "https://github.com/alice", false, 1},
        {"Dorks", "exact", "Alice", "https://github.com/alice?tab=stars", false, 1},
        {"GitHub", "profile", "Alice", "https://github.com/alice", false, 1},
    }, "", true);
    assert(sections.size() == 2 && sections[0].members.size() == 2 && sections[1].members.front() == 0);

    const std::vector<Finding> findings = {
        {"Dorks", "profile search", "Repository tab snippet", "https://www.github.com/Alice?tab=repositories&q=demo", false, 1},
        {"Lookup links", "code: GitHub", "https://github.com/alice/", "https://github.com/alice/", false, 1},
        {"GitHub", "profile", "https://github.com/Alice", "https://github.com/Alice", false, 1},
        {"Dorks", "repository", "A separate repository", "https://github.com/alice/demo", false, 1},
        {"Dorks", "weak profile", "Unrelated snippet", "https://github.com/alice?tab=stars", false, 1},
        {"GitHub", "profile", "https://github.com/alice", "https://github.com/alice", false, 2},
        {"GitHub", "profile", "https://github.com/Alice", "https://github.com/Alice", false, 1},
        {"Dorks", "linked email", "alice@example.test", "", true, 1},
        {"GitHub", "commit email", "alice@example.test", "", true, 1},
        {"Dorks", "search", "Separate query", "https://github.com/alice?foo=1", false, 1},
        {"Dorks", "exact URL match", "Another snippet", "https://github.com/alice/demo", false, 1},
    };
    auto grouped = group_findings(findings, "", true);
    assert(grouped.size() == 5 && grouped.front().members.front() == 5);
    assert(grouped[1].id == 0 && grouped[1].members.size() == 3 && grouped[1].members.front() == 2);
    assert(grouped[1].profile_url == "https://github.com/alice");
    assert(grouped[2].members.size() == 2 && findings[grouped[2].members.front()].pivot);
    auto by_snippet = group_findings(findings, "repository tab snippet", true);
    assert(by_snippet.size() == 1 && by_snippet.front().members.size() == 3);
    auto by_repo = group_findings(findings, "another snippet", true);
    assert(by_repo.size() == 1 && by_repo.front().members.size() == 2 && by_repo.front().profile_url.empty());
    assert(group_findings(findings, "unrelated snippet", true).empty());
    assert(group_findings(findings, "unrelated snippet", false).front().members.size() == 4);
    assert(finding_text("  One\r\n two\t words  ") == "One two words");

    std::istringstream proxy_list("# authorized proxies\r\n"
                                  "  http://proxy.example.test:8080/  \n"
                                  "http://proxy.example.test:8080\n"
                                  "socks5h://[2001:db8::1]:1080\n");
    const auto proxies = read_search_proxies(proxy_list);
    assert(proxies.size() == 2 && proxies[0] == "http://proxy.example.test:8080" &&
           proxies[1] == "socks5h://[2001:db8::1]:1080");
    for (const char* invalid : {"# comment only", "https://proxy.test:65536", "http://proxy.test:0",
                                "http://user:pass@proxy.test:8080", "https://proxy.test:443/path",
                                "http://proxy.test", "ftp://proxy.test:80"}) {
        std::istringstream config(invalid);
        bool rejected = false;
        try { read_search_proxies(config); }
        catch (const std::runtime_error&) { rejected = true; }
        assert(rejected);
    }

    CaseData investigation{
        {
            {"Dorks", "Linked username", "alice", "https://example.test/profile", true, 1,
             {"Fixture Engine", "contact 6502530000", "Exact target mention", 123456, 1, "Reviewed source"}},
            {"Auto dorking", "Profile", "Alice", "https://example.test/profile#about", false, 2},
            {"Lookup links", "Manual search", "example", "https://example.test/?q=manual", false, 2,
             {"", "", "Navigation link"}},
        },
        {{"+16502530000", Phone, 0, 0, "completed"},
         {"alice", Username, 1, 0, "completed", 1}},
        {"fixture log"},
    };
    const auto saved_case = case_json(investigation);
    const auto reopened = parse_case(nlohmann::json::parse(saved_case.dump()));
    assert(case_json(reopened) == saved_case);
    assert(reopened.runs[1].parent_evidence == 1);
    assert(reopened.findings[0].evidence.note == "Reviewed source");
    const auto report = case_report(reopened);
    assert(report.find("pivot from evidence E1") != report.npos);
    assert(report.find("Sources (1 distinct URLs)") != report.npos);
    assert(report.find("https://example.test/profile") != report.npos);
    assert(report.find("Reviewed source") != report.npos);
    assert(report.find("6502530000") != report.npos);
    assert(report.find("?q=manual") == report.npos);
    auto invalid_case = saved_case;
    invalid_case["runs"][1]["parent_evidence"] = 2;
    bool rejected_case = false;
    try { parse_case(invalid_case); }
    catch (const std::runtime_error&) { rejected_case = true; }
    assert(rejected_case);

    assert(normalize_domain("Mail.Example.TEST.") == "mail.example.test");
    for (const auto* input : {"127.0.0.1", "bad..test", "bad.test/path", "a@example.test", "-bad.test", "bad.test:80"})
        assert(normalize_domain(input).empty());
    assert(detect("https://example.test/") == Domain && detect("example.test") == Username);
    assert(domain_dns_answers(nlohmann::json::parse(R"({"Status":0,"Answer":[{"type":5,"data":"alias.example.test."},
            {"type":1,"data":"192.0.2.1"},{"type":1,"data":"192.0.2.1"}]})"), 1) ==
            std::vector<std::string>{"192.0.2.1"});
    assert(domain_dns_answers({{"Status", 3}}, 1).empty());
    bool rejected_dns = false;
    try { domain_dns_answers({{"Status", 0}, {"TC", true}}, 1); }
    catch (const std::runtime_error&) { rejected_dns = true; }
    assert(rejected_dns);
    rejected_dns = false;
    try { domain_dns_answers({{"Status", 3}, {"Comment", "Blocked by policy"}}, 1); }
    catch (const std::runtime_error&) { rejected_dns = true; }
    assert(rejected_dns);
    const auto certs = domain_certificate_hits(nlohmann::json::parse(R"([
        {"id":123,"name_value":"example.test\nwww.example.test\nnotexample.test\n*.example.test",
         "not_before":"2023-01-01T00:00:00"}])"), "example.test");
    assert(certs.size() == 3 && certs[0].evidence.source_date == "2023-01-01T00:00:00");

    CaseData domain_case{
        {
            {"Domain DNS", "A", "192.0.2.1", "https://example.test/dns", true, 1,
             {.provider = "DNS", .scope = "A"}, Ip},
            {"Domain DNS", "A", "192.0.2.2", "https://example.test/dns", true, 2,
             {.provider = "DNS", .scope = "A"}, Ip},
            {"Domain DNS", "MX", "mail.example.test", "", true, 1, {.provider = "DNS", .scope = "MX"}, Domain},
            {"Domain DNS", "NS", "ns.example.test", "", true, 1, {.provider = "DNS", .scope = "NS"}, Domain},
            {"Domain DNS", "TXT", "new verification", "", false, 2, {.provider = "DNS", .scope = "TXT"}},
            {"Domain RDAP", "Registrar", "Example", "", false, 1, {.provider = "RDAP", .scope = "registration"}},
            {"Domain RDAP", "Registrar", "Example", "", false, 2, {.provider = "RDAP", .scope = "registration"}},
        },
        {{"example.test", Domain, 0, 0, "completed", 0,
          {{"DNS", "A", CoverageState::Complete, true}, {"DNS", "MX", CoverageState::Complete, true},
           {"DNS", "NS", CoverageState::Complete, true}, {"DNS", "TXT", CoverageState::Empty, true}}},
         {"example.test", Domain, 0, 0, "completed", 0,
          {{"DNS", "A", CoverageState::Complete, true}, {"DNS", "MX", CoverageState::Blocked},
           {"DNS", "NS", CoverageState::Empty, true}, {"DNS", "TXT", CoverageState::Complete, true}}}},
        {},
    };
    const auto domain_saved = case_json(domain_case);
    const auto domain_replay = parse_case(nlohmann::json::parse(domain_saved.dump()));
    assert(case_json(domain_replay) == domain_saved && domain_replay.findings[2].pivot_type == Domain);
    const auto changes = compare_runs(domain_replay, 1, 2);
    auto has_change = [&](std::string_view state, std::size_t old_id, std::size_t new_id) {
        return std::ranges::any_of(changes, [&](const auto& row) {
            return row.state == state && row.before == old_id && row.after == new_id;
        });
    };
    assert(has_change("Changed", 1, 2) && has_change("Unknown coverage", 3, 0));
    assert(has_change("Absent in recheck", 4, 0) && has_change("New", 0, 5) && has_change("Seen again", 6, 7));
    auto legacy_case = saved_case;
    for (auto& run : legacy_case["runs"]) run.erase("coverage");
    for (auto& f : legacy_case["evidence"])
        for (const char* key : {"pivot_type", "scope", "source_origin", "source_date", "excerpt"}) f.erase(key);
    assert(parse_case(legacy_case).runs[1].parent_evidence == 1);

    CaseData source_case;
    const std::string excerpt = "This example excerpt has enough shared words to match across two publications and does not establish provenance.";
    source_case.findings = {
        {"Dorks", "Lead", "Origin title", "https://news.example.test/article#section", false, 1,
         {.source_date = "2021-08-10", .excerpt = excerpt}},
        {"Domain archive", "Capture", "2023-01-01", "https://archive.example.test/capture", false, 1,
         {.source_origin = "https://NEWS.example.test/article", .source_date = "2023-01-01"}},
        {"Dorks", "Lead", "Different title", "https://copy.example.test/another", false, 1, {.excerpt = excerpt}},
    };
    const auto sources = compare_sources(source_case, 1);
    assert(sources.size() == 2 && sources[0].reason == "Shared recorded origin" &&
           sources[1].reason.find("unconfirmed") != sources[1].reason.npos);

    CaseData phone_case{
        {
            {"Number info", "E.164", "+16502530000", "", false, 1},
            {"Number info", "original carrier", "Old fixture assignment", "", false, 1},
            {"Number info", "E.164", "+16502530000", "", false, 2},
            {"Number info", "original carrier", "New fixture assignment", "", false, 2},
            {"Dorks", "Public match · Example", "alice", "https://example.test/alice", false, 2},
            {"Dorks", "Public match · Example", "alicia", "https://example.test/alicia", false, 2},
        },
        {{"+16502530000", Phone}, {"6502530000", Phone}},
        {},
    };
    const auto triage = phone_summary(phone_case, 2);
    assert(triage.entries.size() == 4 && triage.conflicts.size() == 2);
    std::istringstream carrier_metadata("# Dataset: fixture v2 (imported on a fixture date)\r\n4179|Carrier X");
    std::string dataset;
    assert(carrier_for_prefix(carrier_metadata, "4179000", &dataset) == "Carrier X" &&
           dataset == "fixture v2 (imported on a fixture date)");

    const std::string track = "https://open.spotify.com/track/0123456789abcdefghijAB";
    assert(detect(track) == SpotifyTrack && spotify_track_url(track + "?si=fixture") == track);
    assert(spotify_track_url("spotify:track:0123456789abcdefghijAB") == track);
    assert(spotify_track_url("https://open.spotify.com/intl-de/track/0123456789abcdefghijAB/") == track);
    assert(spotify_track_url("https://open.spotify.com.example.test/track/0123456789abcdefghijAB").empty());
    assert(spotify_track_url("https://open.spotify.com/artist/0123456789abcdefghijAB").empty());
    assert(spotify_username_result({"https://open.spotify.com/user/alice", "", "", {}}, "alice") == "Indexed Spotify user ID");
    assert(spotify_username_result({"https://open.spotify.com/user/alice2", "Alice", "", {}}, "alice").empty());
    assert(spotify_username_result({track, "A track by Alice", "", {}}, "alice") == "Spotify track lead");
    assert(soundcloud_embed_title({{"provider_name", "SoundCloud"}, {"type", "rich"},
                                  {"html", "<iframe src=\"https://w.soundcloud.com/player/?url=fixture\"></iframe>"},
                                  {"title", "Alice"}, {"author_url", "https://soundcloud.com/alice/"}},
                                  "https://soundcloud.com/alice") == "Alice");
    assert(soundcloud_embed_title({{"provider_name", "SoundCloud"}, {"type", "rich"}, {"title", "Generic page"}},
                                  "https://soundcloud.com/alice").empty());
    const std::string recording_id = "f2e893b4-401c-42c4-a4a6-96e56c63f876";
    const auto linked_recording = nlohmann::json::parse(R"({
        "resource": "https://open.spotify.com/track/0123456789abcdefghijAB",
        "relations": [
            {"target-type": "recording", "recording": {"id": "f2e893b4-401c-42c4-a4a6-96e56c63f876"}},
            {"target-type": "release", "release": {"id": "f2e893b4-401c-42c4-a4a6-96e56c63f876"}}
        ]})");
    assert(musicbrainz_linked_recordings(linked_recording, track) == std::vector<std::string>{recording_id});
    assert(musicbrainz_linked_recordings(linked_recording, track + "wrong").empty());
    assert(spotify_public_artist("<title>Song &amp; More - Song, Lyrics, and Music Video by Alice | Spotify</title>",
                                 "Song & More") == "Alice");
    assert(spotify_public_artist("<title>Some other track - Song, Lyrics, and Music Video by Alice | Spotify</title>",
                                 "Song & More").empty());
    auto search = nlohmann::json::parse(R"({"count":1,"recordings":[{
        "id":"f2e893b4-401c-42c4-a4a6-96e56c63f876","title":"Song & More",
        "artist-credit":[{"name":"Alice","artist":{"name":"Alice Example"}}]
    }]})");
    assert(musicbrainz_title_artist_match(search, "Song & More", "Alice") == recording_id);
    assert(musicbrainz_title_artist_match(search, "Song & More", "Another Alice").empty());
    auto second = search["recordings"][0];
    second["id"] = "55555555-5555-5555-5555-555555555555";
    search["recordings"].push_back(second);
    search["count"] = 2;
    assert(musicbrainz_title_artist_match(search, "Song & More", "Alice").empty());
    search["count"] = 30;
    assert(musicbrainz_title_artist_match(search, "Song & More", "Alice").empty());

    const auto credits = musicbrainz_recording_credits(nlohmann::json::parse(R"({
        "id":"f2e893b4-401c-42c4-a4a6-96e56c63f876",
        "relations":[
          {"target-type":"artist","type":"producer","target-credit":"Producer Alias","artist":{"name":"Producer Example"}},
          {"target-type":"artist","type":"tribute","artist":{"name":"Unrelated"}},
          {"target-type":"work","type":"performance","work":{
            "id":"11111111-1111-1111-1111-111111111111","relations":[
              {"target-type":"artist","type":"lyricist","artist":{"name":"Renée Fixture"}},
              {"target-type":"artist","type":"composer","artist":{"name":"Alice Example"}}
            ]}}
        ]})"));
    assert(credits.size() == 3 && credits[0].name == "Producer Alias" && credits[0].role == "Producer" &&
           credits[1].role == "Lyricist" && credits[1].name == "Renée Fixture" &&
           credits[2].source.starts_with("https://musicbrainz.org/work/"));

    CaseData music_case{{{"Spotify credits", "Songwriter", "Alice Example", track, false, 1},
                          {"Spotify credits", "Producer", "Producer Example", track, false, 1}},
                         {{track, SpotifyTrack}}, {}};
    assert(group_findings(music_case.findings, "", true).size() == 2);
    assert(parse_case(case_json(music_case)).runs[0].type == SpotifyTrack);

    assert(normalize_username("  @Ali ce\tSmith ") == "AliceSmith");
    assert(detect("@Ali ce") == Username);
    assert(normalize_username("alice/../../").empty());
    assert(normalize_username(" .. ").empty());
    const auto profile_urls = social_profile_urls(" a lice ");
    assert(profile_urls.size() == 18);
    assert(profile_urls[0].url == "https://x.com/alice" && profile_urls[1].url == "https://instagram.com/alice");
    assert(profile_urls[2].url == "https://facebook.com/alice" && profile_urls[3].url == "https://www.tiktok.com/@alice");
    const auto expected_urls = std::vector<std::pair<std::string_view, std::string_view>>{
        {"SoundCloud", "https://soundcloud.com/alice"},
        {"Last.fm", "https://www.last.fm/user/alice"},
        {"Letterboxd", "https://letterboxd.com/alice"},
        {"GitLab", "https://gitlab.com/alice"},
        {"DEV Community", "https://dev.to/alice"},
        {"Behance", "https://www.behance.net/alice"},
        {"Medium", "https://medium.com/@alice"},
        {"Vimeo", "https://vimeo.com/alice"},
        {"Solo.to", "https://solo.to/alice"},
        {"Cash App", "https://cash.app/$alice"},
        {"Carrd", "https://alice.carrd.co/"},
    };
    for (const auto& [platform, url] : expected_urls) {
        const auto found = std::ranges::find(profile_urls, platform, &SocialProfile::platform);
        assert(found != profile_urls.end() && found->url == url);
    }
    assert(detect("$ali ce") == Username && normalize_username("$ali ce") == "alice");
    const auto cash_app = std::ranges::find(profile_urls, "Cash App", &SocialProfile::platform);
    assert(potential_social_account(*cash_app, "https://cash.app/%24Alice", 200, "<title>Alice on Cash App</title>"));
    assert(!potential_social_account(*cash_app, "https://cash.app/", 200, "<title>Cash App</title>"));
    const auto dotted_urls = social_profile_urls("alice.dot");
    assert(std::ranges::find(dotted_urls, "Carrd", &SocialProfile::platform) == dotted_urls.end());
    assert(std::ranges::find(dotted_urls, "Cash App", &SocialProfile::platform) == dotted_urls.end());
    const auto carrd = std::ranges::find(profile_urls, "Carrd", &SocialProfile::platform);
    assert(potential_social_account(*carrd, "https://Alice.carrd.co", 200, "<title>Alice’s links</title>"));
    assert(!potential_social_account(*carrd, "https://carrd.com/", 200, "<title>Carrd</title>"));
    assert(!potential_social_account(*carrd, "", 200, "<title>Site not found</title>"));
    const auto numeric_urls = social_profile_urls("123456");
    assert(std::ranges::find(numeric_urls, "Vimeo", &SocialProfile::platform) == numeric_urls.end());
    const auto last_fm = std::ranges::find(profile_urls, "Last.fm", &SocialProfile::platform);
    assert(potential_social_account(*last_fm, "https://last.fm/user/Alice/", 200, "<title>Alice’s profile</title>"));
    assert(!potential_social_account(*last_fm, "https://last.fm/user/alice/library", 200, "<title>Alice’s library</title>"));
    auto soundcloud_group = group_findings({
        {"SoundCloud", "Potential account · SoundCloud", "alice", "https://soundcloud.com/alice", false, 1},
        {"Social profiles", "Potential account · SoundCloud", "alice", "https://soundcloud.com/alice", false, 1},
    }, "", true);
    assert(soundcloud_group.size() == 1 && soundcloud_group[0].members.front() == 1);

    assert(social_profile_urls(" Log In ").empty());
    const auto stripchat_rule = std::ranges::find_if(bundled, [](const auto& row) {
        return row.value("name", "") == "Stripchat";
    });
    assert(stripchat_rule != bundled.end() && stripchat_rule->at("headers").at("Accept") == "text/html");
    const SocialProfile stripchat{"Stripchat", "https://stripchat.com/alice"};
    assert(potential_social_account(stripchat, "https://www.stripchat.com/Alice/", 200, "<title>Stripchat</title>"));
    assert(!potential_social_account(stripchat, "", 404, "<title>Stripchat</title>"));
    assert(!potential_social_account(stripchat, "", 200, "<title>404 | Stripchat</title>"));
    assert(!potential_social_account(stripchat, "", 200, "<title>Model not found</title>"));
    assert(!potential_social_account(stripchat, "", 403, "<title>Stripchat</title>"));
    assert(!potential_social_account(stripchat, "", 202, "<title>Stripchat</title>"));
    assert(!potential_social_account(stripchat, "https://stripchat.com/", 200, "<title>Stripchat</title>"));
    const auto& instagram = profile_urls[1];
    assert(potential_social_account(instagram, "https://www.instagram.com/Alice/?hl=en", 200, "<title>Alice</title>"));
    assert(!potential_social_account(instagram, "https://www.instagram.com/accounts/login/?next=/alice", 200, "<title>Alice</title>"));
    assert(!potential_social_account(instagram, "https://instagram.com.example.test/alice", 200, "<title>Alice</title>"));
    assert(!potential_social_account(instagram, "", 200, "<title>Page not found - Instagram</title>"));
    assert(!potential_social_account(instagram, "", 200, "<TITLE>Log in • Instagram</TITLE>"));
    assert(!potential_social_account(instagram, "", 200, "<title>Instagram</title>"));
    assert(!potential_social_account(instagram, "", 200, "<form id=\"challenge-form\"></form>"));
    assert(!potential_social_account(instagram, "", 429, "<title>Alice</title>"));

    const auto fallback = whatsmyname_fallback("@Ali ce", 2);
    assert(fallback && fallback->module == whatsmyname_fallback_name && fallback->run_id == 2 &&
           fallback->url == "https://whatsmyname.app/?q=Alice");
    assert(!whatsmyname_fallback("invalid/username", 2));

    const auto imported = import_whatsmyname_csv(
        "\xef\xbb\xbf" "Found Accounts\r\nSite,Category,Link\r\n"
        "\"Example, Inc.\",social,https://example.test/alice\r\n"
        "\"Example, Inc.\",social,https://example.test/alice\r\n"
        "bad,misc,file:///tmp/example\r\n", "alice", 2);
    assert(imported.size() == 1 && imported[0].module == whatsmyname_csv_section && imported[0].run_id == 2 &&
           imported[0].key == "Potential account · Example, Inc.");
    assert(import_whatsmyname_csv("Site,Link,Status\nExample,https://example.test/alice,not found", "alice", 2).empty());
    bool wrong_handle = false;
    try { import_whatsmyname_csv("Site,Link,Username\nExample,https://example.test/bob,bob", "alice", 2); }
    catch (const std::runtime_error&) { wrong_handle = true; }
    assert(wrong_handle);
    assert(group_findings({
        {"Social profiles", "Potential account · Example", "alice", "https://example.test/alice", false, 2},
        imported[0],
    }, "", false).size() == 2);

    // Every module accepts at least one type, and every type has modules
    for (const Module& m : modules()) assert(m.types && m.run && m.name);
    for (Type t : {Phone, Email, Ip, Username, Domain, SpotifyTrack})
        assert(std::any_of(modules().begin(), modules().end(), [&](const Module& m) { return m.types & t; }));

    assert(discord_username(" @Ali_Ce.1 ") == "ali_ce.1");
    assert(discord_username("a").empty() && discord_username(std::string(33, 'a')).empty());
    assert(discord_username("a..b").empty() && discord_username("al-ice").empty());
    assert(plausible_discord_token(std::string(59, 'A') + ".x_-9"));
    assert(!plausible_discord_token("short") && !plausible_discord_token(std::string(60, 'A') + "\r\nX-Injected: 1"));
    assert(std::ranges::find(modules(), std::string_view("Discord"), [](const Module& m) { return std::string_view(m.name); }) != modules().end());

    std::puts("ok");
}
