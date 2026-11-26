// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <cassert>
#include <chrono>
#include <thread>

#include "http.h"
#include "osint.h"

using namespace std::chrono_literals;

int main(int argc, char** argv) {
    assert(argc == 3);
    const std::string base = argv[1];
    const Request fast{.min_interval_s = 0};
    auto get = [&](const std::string& path, const Request& request = {.min_interval_s = 0}) {
        return http_get(base + path, {}, request);
    };

    const auto blocked_proxy = http_get("https://fixture.invalid", {},
                                        {.min_interval_s = 0, .cache = false, .proxy = base});
    assert(blocked_proxy.status == 403 && !blocked_proxy.proxy_unreachable);
    const auto offline_proxy = http_get("https://fixture.invalid", {},
                                        {.min_interval_s = 0, .cache = false, .proxy = argv[2]});
    assert(offline_proxy.status == 0 && offline_proxy.proxy_unreachable);
    const auto default_agent = get("/user-agent");
    const auto marked = get("/user-agent", {.min_interval_s = 0,
                                            .user_agent = "snitch/1.0 (public profile lookup)"});
    assert(marked.status == 200 && marked.body == "snitch/1.0 (public profile lookup)");
    assert(default_agent.status == 200 && default_agent.body != marked.body);
    assert(get("/user-agent").body == default_agent.body);

    assert(get("/html-only").status == 406);
    assert(get("/html-only", {.headers = {"Accept: text/html"}, .min_interval_s = 0}).status == 200);

    const auto cached = get("/count");
    assert(cached.status == 200 && get("/count").body == cached.body);
    const auto custom = get("/count", {.headers = {"X-Test: local"}, .min_interval_s = 0});
    assert(custom.status == 200 && custom.body != cached.body && get("/count").body == cached.body);
    assert(get("/redirect").status == 200);
    const auto limited = get("/limited");
    assert(limited.status == 429 && limited.retry_after);
    const auto oversized = get("/oversized");
    assert(oversized.status == 0 && !oversized.error.empty());
    const auto timeout = get("/slow", {.timeout_s = 1, .min_interval_s = 0});
    assert(timeout.status == 0 && !timeout.error.empty());

    for (int i = 0; i < 128; ++i) assert(get("/count?" + std::to_string(i)).status == 200);
    assert(get("/count").body != cached.body);

    auto cancel = [&](const std::string& path, double interval) {
        std::stop_source stop;
        std::jthread trigger([&] { std::this_thread::sleep_for(150ms); stop.request_stop(); });
        const auto start = std::chrono::steady_clock::now();
        const auto result = http_get(base + path, stop.get_token(), {.min_interval_s = interval, .cache = false});
        assert(result.status == 0 && !result.error.empty());
        assert(std::chrono::steady_clock::now() - start < 3s);
    };
    cancel("/slow", 0);
    assert(get("/pace", {.min_interval_s = 1, .cache = false}).status == 200);
    cancel("/count?canceled", 4);
    const auto start = std::chrono::steady_clock::now();
    assert(get("/count?after", fast).status == 200);
    assert(std::chrono::steady_clock::now() - start < 2s);

    const auto& registry = modules();
    const auto dorks = std::ranges::find_if(registry, [](const Module& mod) {
        return std::string_view(mod.name) == "Dorks";
    });
    assert(dorks != registry.end());
    std::vector<Finding> findings;
    std::vector<std::string> log;
    dorks->run({"mark47-fixture", Username, {.searxng = base}, {},
                [&](Finding f) { findings.push_back(std::move(f)); },
                [&](std::string line) { log.push_back(std::move(line)); }});
    assert(!findings.empty());
    assert(std::ranges::all_of(findings, [](const Finding& f) {
        return f.url.starts_with("https://www.google.com/search?q=");
    }));
    assert(log.size() == 1 && log[0].find("HTTP 429") != std::string::npos);
    assert(get("/search-attempts", {.min_interval_s = 0, .cache = false}).body == "1");

}
