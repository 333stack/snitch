// Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
#include "modules.h"

const std::vector<Module>& modules() {
    static const std::vector<Module> all = [] {
        std::vector<Module> v;
        for (auto* list : {&phone_modules, &email_modules, &username_modules, &social_modules, &music_modules, &ip_modules, &domain_modules, &dork_modules})
            for (const Module& m : list()) v.push_back(m);
        return v;
    }();
    return all;
}
