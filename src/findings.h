// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#pragma once

#include <optional>

#include "osint.h"

struct FindingGroup {
    std::size_t id;  // first member's index, even when a better primary arrives
    std::vector<std::size_t> members;  // primary first
    std::string profile_url;  // canonical GitHub profile, when recognized
};

std::vector<FindingGroup> group_findings(const std::vector<Finding>& findings,
                                         std::string_view filter, bool hide_weak);
std::string finding_text(std::string_view text);


inline constexpr char whatsmyname_fallback_name[] = "WhatsMyName";
std::optional<Finding> whatsmyname_fallback(std::string_view target, std::size_t run_id);

inline constexpr char whatsmyname_csv_section[] = "WhatsMyName (CSV)";
std::vector<Finding> import_whatsmyname_csv(std::string_view csv, std::string_view target, std::size_t run_id);
