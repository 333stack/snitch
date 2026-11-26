// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include "http.h"

#include <curl/curl.h>

#include <algorithm>
#include <chrono>
#include <map>
#include <mutex>
#include <thread>

namespace {
constexpr size_t kMaxBody = 8 << 20;  // a misbehaving server can't eat memory
const char* kAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";

using Clock = std::chrono::steady_clock;
constexpr size_t kCacheBytes = 32 << 20;
constexpr size_t kCacheEntries = 128;
constexpr auto kCacheTtl = std::chrono::minutes(5);

struct CacheEntry {
    Clock::time_point expires;
    Response response;
};

std::mutex g_m;
std::map<std::string, Clock::time_point> g_next;
std::map<std::string, CacheEntry> g_cache;
size_t g_cache_bytes = 0;

void erase_cache(std::map<std::string, CacheEntry>::iterator it) {
    g_cache_bytes -= it->first.size() + it->second.response.body.size() + it->second.response.effective_url.size();
    g_cache.erase(it);
}

void prune_cache(Clock::time_point now) {
    for (auto it = g_cache.begin(); it != g_cache.end();) {
        if (it->second.expires <= now) erase_cache(it++);
        else ++it;
    }
}

std::string host_of(const std::string& url) {
    const size_t s = url.find("://"), b = s == std::string::npos ? 0 : s + 3;
    return url.substr(b, url.find_first_of("/?#", b) - b);
}

size_t on_data(char* p, size_t n, size_t m, void* u) {
    auto* body = static_cast<std::string*>(u);
    if (body->size() + n * m > kMaxBody) return 0;  // aborts the transfer
    body->append(p, n * m);
    return n * m;
}

int on_progress(void* u, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    return static_cast<std::stop_token*>(u)->stop_requested();  // nonzero aborts
}

const bool g_init = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
}  // namespace

std::string url_encode(std::string_view s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char ch : s) {
        if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') out += char(ch);
        else { out += '%'; out += hex[ch >> 4]; out += hex[ch & 15]; }
    }
    return out;
}

Response http_get(const std::string& url, std::stop_token stop, const Request& req) {
    Response r;
    if (!g_init) { r.error = "curl init failed"; return r; }
    const bool cache = req.cache && req.headers.empty() && req.post.empty() &&
                       req.proxy.empty() && req.follow_redirects && req.user_agent.empty();
    const std::string host = host_of(url);
    for (;;) {
        if (stop.stop_requested()) { r.error = "stopped"; return r; }
        const auto now = Clock::now();
        auto delay = Clock::duration::zero();
        {
            std::lock_guard l(g_m);
            if (cache) {
                prune_cache(now);
                if (auto it = g_cache.find(url); it != g_cache.end()) return it->second.response;
            }
            std::erase_if(g_next, [now](const auto& item) { return item.second <= now; });
            if (auto it = g_next.find(host); it != g_next.end()) delay = it->second - now;
            else {
                if (req.min_interval_s > 0)
                    g_next[host] = now + std::chrono::duration_cast<Clock::duration>(
                        std::chrono::duration<double>(req.min_interval_s));
                break;
            }
        }
        std::this_thread::sleep_for(std::min(delay, Clock::duration(std::chrono::milliseconds(50))));
    }
    if (stop.stop_requested()) { r.error = "stopped"; return r; }

    CURL* h = curl_easy_init();
    if (!h) { r.error = "curl_easy_init failed"; return r; }
    curl_slist* hdrs = nullptr;
    for (const auto& x : req.headers) hdrs = curl_slist_append(hdrs, x.c_str());
    curl_easy_setopt(h, CURLOPT_URL, url.c_str());
    curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "http,https");  // targets end up in URLs: no file://, gopher:// etc.
    curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, req.follow_redirects ? 1L : 0L);
    curl_easy_setopt(h, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, req.timeout_s);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(h, CURLOPT_USERAGENT, req.user_agent.empty() ? kAgent : req.user_agent.c_str());
    curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_data);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &r.body);
    curl_easy_setopt(h, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(h, CURLOPT_XFERINFOFUNCTION, on_progress);
    curl_easy_setopt(h, CURLOPT_XFERINFODATA, &stop);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);  // required with threads
    if (!req.post.empty()) curl_easy_setopt(h, CURLOPT_POSTFIELDS, req.post.c_str());
    if (!req.proxy.empty()) {
        curl_easy_setopt(h, CURLOPT_PROXY, req.proxy.c_str());
        curl_easy_setopt(h, CURLOPT_NOPROXY, "");  // explicit routing also applies when no_proxy is set
    }
    const auto result = curl_easy_perform(h);
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &r.status);
    unsigned int header_origin = CURLH_HEADER;
    if (result != CURLE_OK) {
        r.error = curl_easy_strerror(result);
        if (!req.proxy.empty()) {
            long connect_status = 0, redirects = 0;
            char* peer = nullptr;
            curl_easy_getinfo(h, CURLINFO_HTTP_CONNECTCODE, &connect_status);
            curl_easy_getinfo(h, CURLINFO_REDIRECT_COUNT, &redirects);
            curl_easy_getinfo(h, CURLINFO_PRIMARY_IP, &peer);
            // Relay a refused CONNECT as an HTTP response, never as a proxy outage.
            if (!r.status && connect_status && connect_status != 200) {
                r.status = connect_status;
                header_origin = CURLH_CONNECT;
            }
            r.proxy_unreachable = !r.status && !connect_status && !redirects &&
                (result == CURLE_COULDNT_RESOLVE_PROXY ||
                 (result == CURLE_COULDNT_CONNECT && (!peer || !*peer)));
        }
        // Preserve the existing status-zero contract for partial provider transfers.
        if (req.proxy.empty() || (header_origin == CURLH_HEADER &&
            r.status != 202 && r.status != 403 && r.status != 407 && r.status != 429)) r.status = 0;
    }
    if (result == CURLE_OK) {
        char* effective = nullptr;
        curl_easy_getinfo(h, CURLINFO_EFFECTIVE_URL, &effective);
        if (effective && url != effective) r.effective_url = effective;
    }
    curl_header* header = nullptr;
    r.retry_after = curl_easy_header(h, "Retry-After", 0, header_origin, -1, &header) == CURLHE_OK;
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(h);

    const size_t bytes = url.size() + r.body.size() + r.effective_url.size();
    if (cache && !stop.stop_requested() && r.status == 200 && !r.retry_after && bytes <= kCacheBytes) {
        std::lock_guard l(g_m);
        const auto now = Clock::now();
        prune_cache(now);
        if (auto it = g_cache.find(url); it != g_cache.end()) erase_cache(it);
        while (g_cache.size() >= kCacheEntries || g_cache_bytes + bytes > kCacheBytes) {
            erase_cache(std::ranges::min_element(g_cache, {}, [](const auto& item) {
                return item.second.expires;
            }));
        }
        g_cache.emplace(url, CacheEntry{now + kCacheTtl, r});
        g_cache_bytes += bytes;
    }
    return r;
}
