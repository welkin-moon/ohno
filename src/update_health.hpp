#pragma once
#include "update_transaction.hpp"
namespace ohno {
// Private inherited pipe only. A public pipe, SCM RUNNING or reachability is
// never accepted as health. Binding is checked against the launched revision.
inline std::string serialize_update_health(const UpdateHealth& proof) {
    transaction_detail::revision(proof.revision);
    if(!update_detail::lower_hex(proof.transaction,64)||!proof.successful_agent_cycles||
       proof.successful_agent_cycles>max_update_sequence)throw std::runtime_error("invalid worker health");
    return "{\"transaction\":\""+proof.transaction+"\",\"revision\":"+
        transaction_detail::encode_revision(proof.revision)+",\"cycles\":"+
        std::to_string(proof.successful_agent_cycles)+"}\n";
}
inline UpdateHealth parse_update_health(const std::string& document) {
    if(document.size()>512)throw std::runtime_error("worker health too large");
    const auto value=ohno_json::parse(document);
    if(value.type!=ohno_json::value::kind::object||value.fields.size()!=3)
        throw std::runtime_error("unknown worker health fields");
    UpdateHealth result{update_detail::text(value,"transaction"),
        transaction_detail::decode_revision(value.at("revision")),
        update_detail::integer(value,"cycles",1,max_update_sequence)};
    serialize_update_health(result);return result;
}
}
