// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include <arpa/inet.h>

#include <stdexcept>

#include "http.h"
#include "nlohmann/json.hpp"
#include "osint.h"

using json = nlohmann::json;

static json get_json(const std::string& url, const Job& j, std::initializer_list<long> ok_missing = {}) {
    const Response r = http_get(url, j.stop);
    for (long s : ok_missing) if (r.status == s) return nullptr;
    if (r.status != 200) throw std::runtime_error(r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    return json::parse(r.body);
}

static std::string ptr_name(const std::string& ip) {
    in6_addr a6;
    in_addr a4;
    std::string out;
    if (inet_pton(AF_INET, ip.c_str(), &a4) == 1) {
        auto* b = reinterpret_cast<const unsigned char*>(&a4);
        for (int i = 3; i >= 0; i--) out += std::to_string(b[i]) + ".";
        return out + "in-addr.arpa";
    }
    if (inet_pton(AF_INET6, ip.c_str(), &a6) != 1) throw std::runtime_error("not an IP");
    static const char* hex = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        out += hex[a6.s6_addr[i] & 15]; out += '.';
        out += hex[a6.s6_addr[i] >> 4]; out += '.';
    }
    return out + "ip6.arpa";
}

static void reverse_dns(const Job& j) {
    const auto names = doh(ptr_name(j.target), "PTR", j.stop);
    if (names.empty()) j.log("no PTR record");
    for (const auto& n : names) {
        if (const auto host = normalize_domain(n); !host.empty())
            j.pivot("hostname", host, "", {.provider = "Cloudflare DoH", .basis = "PTR answer"}, Domain);
        else j.add("hostname", n);
    }
}

static void rdap(const Job& j) {
    const json d = get_json("https://rdap.org/ip/" + j.target, j);
    j.add("network", d.value("name", "") + " (" + d.value("handle", "") + ")", "https://rdap.org/ip/" + j.target);
    j.add("range", d.value("startAddress", "") + " - " + d.value("endAddress", ""));
    if (d.contains("country")) j.add("country", d["country"].get<std::string>());
    // vCard arrays: ["vcard", [["fn", {}, "text", "Name"], ["email", {}, "text", "a@b"], ...]]
    std::function<void(const json&)> walk = [&](const json& ents) {
        for (const auto& e : ents) {
            std::string roles;
            for (const auto& r : e.value("roles", json::array())) roles += (roles.empty() ? "" : ",") + r.get<std::string>();
            if (e.contains("vcardArray") && e["vcardArray"].size() > 1)
                for (const auto& f : e["vcardArray"][1]) {
                    const std::string k = f[0];
                    if ((k == "fn" || k == "email" || k == "tel" || k == "adr") && f.size() > 3) {
                        std::string v = f[3].is_string() ? f[3].get<std::string>() : f[3].dump();
                        if (k == "adr" && f[1].contains("label")) v = f[1]["label"].get<std::string>();
                        for (size_t p = v.find('\n'); p != std::string::npos; p = v.find('\n', p)) v.replace(p, 1, ", ");
                        if (k == "email") j.pivot(roles + " email", v);
                        else j.add(roles + " " + k, v);
                    }
                }
            if (e.contains("entities")) walk(e["entities"]);
        }
    };
    if (d.contains("entities")) walk(d["entities"]);
}

static void asn(const Job& j) {
    const json d = get_json("https://stat.ripe.net/data/prefix-overview/data.json?resource=" + url_encode(j.target), j)["data"];
    j.add("prefix", d.value("resource", ""));
    for (const auto& a : d.value("asns", json::array()))
        j.add("ASN", "AS" + std::to_string(a.value("asn", 0)) + " " + a.value("holder", ""),
              "https://bgp.he.net/AS" + std::to_string(a.value("asn", 0)));
}

static void internetdb(const Job& j) {
    const json d = get_json("https://internetdb.shodan.io/" + j.target, j, {404});
    if (d.is_null()) { j.log("no Shodan data for this IP"); return; }
    auto list = [&](const char* field, const char* label) {
        for (const auto& v : d.value(field, json::array())) j.add(label, v.is_string() ? v.get<std::string>() : v.dump());
    };
    list("ports", "open port");
    list("hostnames", "hostname");
    list("tags", "tag");
    list("cpes", "software");
    for (const auto& v : d.value("vulns", json::array()))
        j.add("vuln", v.get<std::string>(), "https://nvd.nist.gov/vuln/detail/" + v.get<std::string>());
}

static void tor(const Job& j) {
    const Response r = http_get("https://check.torproject.org/torbulkexitlist", j.stop);
    if (r.status != 200) throw std::runtime_error(r.error.empty() ? "HTTP " + std::to_string(r.status) : r.error);
    const std::string needle = "\n" + j.target + "\n";
    j.add("tor exit", ("\n" + r.body + "\n").find(needle) != std::string::npos ? "yes" : "no (not in current exit list)");
}

static void geo(const Job& j) {
    // ip-api free tier: HTTP only, non-commercial, 45 req/min.
    const json d = get_json("http://ip-api.com/json/" + j.target +
                                "?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting",
                            j);
    if (d.value("status", "") != "success") throw std::runtime_error(d.value("message", "lookup failed"));
    j.add("location", d.value("city", "") + ", " + d.value("regionName", "") + " " + d.value("zip", "") + ", " + d.value("country", ""),
          "https://www.openstreetmap.org/?mlat=" + std::to_string(d.value("lat", 0.0)) + "&mlon=" + std::to_string(d.value("lon", 0.0)));
    j.add("timezone", d.value("timezone", ""));
    j.add("isp", d.value("isp", "") + " / " + d.value("org", ""));
    std::string flags;
    for (const char* f : {"mobile", "proxy", "hosting"}) if (d.value(f, false)) flags += std::string(flags.empty() ? "" : ", ") + f;
    j.add("flags", flags.empty() ? "none" : flags);
}

const std::vector<Module>& ip_modules() {
    static const std::vector<Module> m = {
        {"Reverse DNS", "PTR record via DNS-over-HTTPS (Cloudflare)", Ip, reverse_dns},
        {"RDAP", "Network owner, range, abuse/admin contacts (rdap.org)", Ip, rdap},
        {"ASN", "Prefix and AS holder (RIPEstat)", Ip, asn},
        {"Shodan InternetDB", "Open ports, software, CVEs (free, no key)", Ip, internetdb},
        {"Tor exit", "Is it a current Tor exit node", Ip, tor},
        {"Geo (ip-api)", "City-level location, ISP, proxy/hosting flags (HTTP, non-commercial)", Ip, geo},
    };
    return m;
}
