#pragma once
#include "../src/update_manifest.hpp"
namespace ohno {
// Integrity check for an ALREADY installed, journal-bound release; does not
// authorize a new update or bypass offer freshness/replay checks.
UpdateManifest verify_update_signature(const std::string& document, const std::string& pinned_public_key);
// School key is installed out-of-band; never accept a key supplied by an offer.
// Throws on malformed/unauthenticated/stale offers. No filesystem/SCM side effects.
UpdateManifest verify_update_offer(const std::string& document, const std::string& pinned_public_key,
    std::uint64_t installed_sequence, std::uint64_t updater_version, std::uint64_t now);
}
