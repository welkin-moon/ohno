#pragma once
#include "update_manifest.hpp"
#include <utility>

namespace ohno {
// Pure transition logic. Nothing here authenticates a package, writes a file,
// stops a service or executes code. The runtime must durably stage/verify the
// complete package before prepare, durably persist each returned record before
// acting, and obtain health only from its own spawned worker's private IPC.
struct UpdateRevision {
    std::uint64_t sequence = 0;
    std::string version, sha256;
};
inline bool operator==(const UpdateRevision& a, const UpdateRevision& b) {
    return a.sequence == b.sequence && a.version == b.version && a.sha256 == b.sha256;
}
inline bool operator!=(const UpdateRevision& a, const UpdateRevision& b) { return !(a == b); }
enum class UpdatePhase { Stable, Prepared, Probation };
struct UpdateJournal {
    std::uint64_t generation = 1, high_water = 0;
    UpdatePhase phase = UpdatePhase::Stable;
    UpdateRevision active, last_good, candidate;
    std::string transaction;
};
struct UpdateHealth {
    std::string transaction;
    UpdateRevision revision;
    std::uint64_t successful_agent_cycles = 0;
};
namespace transaction_detail {
inline bool empty(const UpdateRevision& r) { return r.sequence == 0 && r.version.empty() && r.sha256.empty(); }
inline void revision(const UpdateRevision& r) {
    if (r.sequence > max_update_sequence || !update_detail::version(r.version) ||
        !update_detail::lower_hex(r.sha256, 64)) throw std::runtime_error("invalid update revision");
}
inline const char* phase(UpdatePhase p) {
    switch (p) {
        case UpdatePhase::Stable: return "stable";
        case UpdatePhase::Prepared: return "prepared";
        case UpdatePhase::Probation: return "probation";
    }
    throw std::runtime_error("unknown update phase");
}
inline void validate(const UpdateJournal& s) {
    if (!s.generation || s.generation > max_update_sequence || s.high_water > max_update_sequence)
        throw std::runtime_error("invalid journal generation or floor");
    revision(s.active); revision(s.last_good);
    if (s.active.sequence > s.high_water || s.last_good.sequence > s.high_water)
        throw std::runtime_error("journal replay floor decreased");
    if (s.phase == UpdatePhase::Stable) {
        if (s.active != s.last_good || !empty(s.candidate) || !s.transaction.empty())
            throw std::runtime_error("inconsistent stable journal");
    } else if (s.phase == UpdatePhase::Prepared || s.phase == UpdatePhase::Probation) {
        revision(s.candidate);
        if (!update_detail::lower_hex(s.transaction, 64) || s.candidate.sequence <= s.last_good.sequence ||
            s.candidate.sequence != s.high_water ||
            s.active != (s.phase == UpdatePhase::Prepared ? s.last_good : s.candidate))
            throw std::runtime_error("inconsistent pending journal");
    } else throw std::runtime_error("unknown update phase");
}
inline UpdateJournal advance(const UpdateJournal& state) {
    validate(state);
    if (state.generation == max_update_sequence) throw std::runtime_error("journal generation exhausted");
    auto next = state; ++next.generation; return next;
}
inline std::string encode_revision(const UpdateRevision& r) {
    return "{\"sequence\":" + std::to_string(r.sequence) + ",\"version\":\"" + r.version +
        "\",\"sha256\":\"" + r.sha256 + "\"}";
}
inline UpdateRevision decode_revision(const ohno_json::value& value) {
    if (value.type != ohno_json::value::kind::object || value.fields.size() != 3)
        throw std::runtime_error("invalid revision fields");
    return {update_detail::integer(value, "sequence", 0, max_update_sequence),
        update_detail::text(value, "version"), update_detail::text(value, "sha256")};
}
}
inline UpdateJournal initial_update_journal(const UpdateRevision& installed) {
    transaction_detail::revision(installed);
    UpdateJournal s; s.active = s.last_good = installed; s.high_water = installed.sequence;
    return s;
}
inline std::string serialize_update_journal(const UpdateJournal& state) {
    transaction_detail::validate(state);
    return "{\"schema\":1,\"generation\":" + std::to_string(state.generation) +
        ",\"high_water\":" + std::to_string(state.high_water) + ",\"phase\":\"" +
        transaction_detail::phase(state.phase) + "\",\"active\":" + transaction_detail::encode_revision(state.active) +
        ",\"last_good\":" + transaction_detail::encode_revision(state.last_good) + ",\"candidate\":" +
        transaction_detail::encode_revision(state.candidate) + ",\"transaction\":\"" + state.transaction + "\"}\n";
}
inline UpdateJournal parse_update_journal(const std::string& document) {
    if (document.size() > 4096) throw std::runtime_error("journal too large");
    auto value = ohno_json::parse(document);
    if (value.type != ohno_json::value::kind::object || value.fields.size() != 8 ||
        update_detail::integer(value, "schema", 1, 1) != 1) throw std::runtime_error("unknown journal schema");
    UpdateJournal s;
    s.generation = update_detail::integer(value, "generation", 1, max_update_sequence);
    s.high_water = update_detail::integer(value, "high_water", 0, max_update_sequence);
    const auto phase = update_detail::text(value, "phase");
    if (phase == "stable") s.phase = UpdatePhase::Stable;
    else if (phase == "prepared") s.phase = UpdatePhase::Prepared;
    else if (phase == "probation") s.phase = UpdatePhase::Probation;
    else throw std::runtime_error("unknown journal phase");
    s.active = transaction_detail::decode_revision(value.at("active"));
    s.last_good = transaction_detail::decode_revision(value.at("last_good"));
    s.candidate = transaction_detail::decode_revision(value.at("candidate"));
    s.transaction = update_detail::text(value, "transaction");
    transaction_detail::validate(s); return s;
}
inline UpdateJournal prepare_update(const UpdateJournal& state, const UpdateRevision& verified,
                                     const std::string& random_transaction) {
    auto next = transaction_detail::advance(state);
    transaction_detail::revision(verified);
    if (state.phase != UpdatePhase::Stable || verified.sequence <= state.high_water ||
        !update_detail::lower_hex(random_transaction, 64)) throw std::runtime_error("update already pending or replayed");
    next.candidate = verified; next.high_water = verified.sequence;
    next.phase = UpdatePhase::Prepared; next.transaction = random_transaction;
    transaction_detail::validate(next); return next;
}
inline UpdateJournal activate_update(const UpdateJournal& state, const std::string& transaction) {
    auto next = transaction_detail::advance(state);
    if (state.phase != UpdatePhase::Prepared || transaction != state.transaction)
        throw std::runtime_error("activation transaction mismatch");
    next.active = next.candidate; next.phase = UpdatePhase::Probation;
    transaction_detail::validate(next); return next;
}
inline UpdateJournal commit_update_health(const UpdateJournal& state, const UpdateHealth& health) {
    auto next = transaction_detail::advance(state);
    if (state.phase != UpdatePhase::Probation || health.transaction != state.transaction ||
        health.revision != state.active || !health.successful_agent_cycles)
        throw std::runtime_error("unbound or incomplete update health proof");
    next.last_good = next.active; next.candidate = {}; next.transaction.clear(); next.phase = UpdatePhase::Stable;
    transaction_detail::validate(next); return next;
}
inline UpdateJournal rollback_update(const UpdateJournal& state) {
    transaction_detail::validate(state);
    if (state.phase == UpdatePhase::Stable) return state;
    auto next = transaction_detail::advance(state);
    next.active = next.last_good; next.candidate = {}; next.transaction.clear(); next.phase = UpdatePhase::Stable;
    // Never lower high_water: a failed build cannot loop/replay after rollback.
    transaction_detail::validate(next); return next;
}
// After process/OS interruption, any uncommitted transaction rolls back before
// launching anything. Network reachability and SCM RUNNING are not health.
inline UpdateJournal recover_update(const UpdateJournal& persisted) { return rollback_update(persisted); }

// The implementation holds one exclusive installation lock for its lifetime.
// It must atomically replace a bounded record and report durable success only
// after all required writes/flushes. Uncertain writes must stop the current
// attempt, never infer permission to launch from an optimistic memory record.
enum class JournalWrite { Durable, NotWritten, Uncertain };
class UpdateJournalStorage {
public:
    virtual ~UpdateJournalStorage() = default;
    virtual std::string read() = 0;
    virtual JournalWrite replace(const std::string& next) = 0;
};
inline void persist_update_transition(UpdateJournalStorage& storage, const UpdateJournal& expected,
                                      const UpdateJournal& next) {
    const auto before = serialize_update_journal(expected), after = serialize_update_journal(next);
    bool legal = false;
    if (expected.phase == UpdatePhase::Stable && next.phase == UpdatePhase::Prepared)
        legal = serialize_update_journal(prepare_update(expected,next.candidate,next.transaction)) == after;
    else if (expected.phase == UpdatePhase::Prepared && next.phase == UpdatePhase::Probation)
        legal = serialize_update_journal(activate_update(expected,next.transaction)) == after;
    else if (expected.phase != UpdatePhase::Stable && next.phase == UpdatePhase::Stable) {
        legal = serialize_update_journal(rollback_update(expected)) == after;
        if (!legal && expected.phase == UpdatePhase::Probation)
            legal = serialize_update_journal(commit_update_health(expected,{expected.transaction,expected.active,1})) == after;
    }
    if (!legal || serialize_update_journal(parse_update_journal(storage.read())) != before)
        throw std::runtime_error("journal concurrent change or invalid transition");
    if (storage.replace(after) != JournalWrite::Durable)
        throw std::runtime_error("journal write failed or outcome uncertain; recover before acting");
}
}
