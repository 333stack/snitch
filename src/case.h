// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#pragma once

#include "nlohmann/json.hpp"
#include "osint.h"

struct Run {
    std::string target;
    Type type;
    std::size_t parent = 0;
    std::size_t errors = 0;
    std::string outcome = "running";
    std::size_t parent_evidence = 0;
    std::vector<Coverage> coverage;
};

struct CaseData {
    std::vector<Finding> findings;
    std::vector<Run> runs;
    std::vector<std::string> log;
};

nlohmann::json case_json(const CaseData& data);
CaseData parse_case(const nlohmann::json& data);
std::string case_report(const CaseData& data);

const char* coverage_name(CoverageState state);

struct CaseChange {
    std::string state;
    std::size_t before = 0, after = 0;  // evidence IDs
};
std::vector<CaseChange> compare_runs(const CaseData& data, std::size_t before, std::size_t after);

struct SourceMatch {
    std::size_t evidence_id;
    std::string reason;
};
std::vector<SourceMatch> compare_sources(const CaseData& data, std::size_t evidence_id);
struct PhoneReview {
    std::vector<std::size_t> entries;
    std::vector<std::string> conflicts;
};
PhoneReview phone_summary(const CaseData& data, std::size_t run_id);
