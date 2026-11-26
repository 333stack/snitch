// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#pragma once
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

struct Response {
    long status = 0;      // 0 = transport failure, see error
    std::string body, error;
    bool retry_after = false;
    std::string effective_url;
    bool proxy_unreachable = false;  // failure before reaching an explicitly configured proxy
};

struct Request {
    std::vector<std::string> headers;  // "Name: value"
    long timeout_s = 15;
    double min_interval_s = 1.0;       // per host; scraped search engines want more
    bool cache = true;                 // reuse a fresh HTTP 200 for a plain GET
    std::string post;                  // non-empty = POST this body
    std::string proxy;                 // optional explicit proxy URL
    bool follow_redirects = true;
    std::string user_agent;            // empty uses the transport default
};

Response http_get(const std::string& url, std::stop_token stop = {}, const Request& req = {});
std::string url_encode(std::string_view s);
