# snitch

snitch is an OSINT workbench for public information. Give it a phone number, email address, IP, username, domain or Spotify track URL: it detects the type, runs every enabled lookup module for it at once, and collects the results as findings you can review, pivot from and export as a case report.

Built on **kitui**, my own immediate-mode C++ UI library (private for now), so it's a small native app with a GPU-drawn interface.

- Usage, modules, dorking, architecture and change log: [DOCUMENTATION.md](DOCUMENTATION.md)
- Status and plan: [TODO.md](TODO.md)

## Build

Linux only for now. Needs kitui checked out next to this folder (`../kitui`), CMake 3.24+, a C++20 compiler, SDL3, libcurl 7.85+, OpenSSL and libphonenumber.
```sh
cmake -S . -B build && cmake --build build
./build/snitch [target]
ctest --test-dir build --output-on-failure
```

Install for your user so `snitch` runs from any terminal (binary in `~/.local/bin`, data in `~/.local/share/snitch`); re-run after rebuilding to update:
```sh
cmake --install build --prefix ~/.local
```

Use it only on targets you're authorised to research, and respect each site's terms.

## License

Copyright 2026 STACK. [PolyForm Noncommercial 1.0.0](LICENSE.md): use, modify and share for noncommercial purposes, always credit the author (keep the `Required Notice` line and the license with every copy), and get written permission before any commercial use. `third_party/nlohmann` is MIT; `data/username-sites.json` is adapted from WhatsMyName under CC BY-SA 4.0.
