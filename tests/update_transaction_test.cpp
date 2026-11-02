#include "update_transaction.hpp"
#include <cassert>
#include <iostream>
#include <functional>
using namespace ohno;
void rejects(const std::function<void()>& f) { bool bad=false; try {f();} catch(const std::exception&){bad=true;} assert(bad); }
struct MemoryDisk : UpdateJournalStorage {
    std::string bytes;
    JournalWrite outcome=JournalWrite::Durable;
    bool uncertain_landed=false;
    std::string read() override {return bytes;}
    JournalWrite replace(const std::string& next) override {
        if(outcome==JournalWrite::Durable || (outcome==JournalWrite::Uncertain && uncertain_landed))bytes=next;
        return outcome;
    }
};
int main() {
    const UpdateRevision old{0,"0.1.0-alpha.6",std::string(64,'a')};
    const UpdateRevision target{7,"0.2.0",std::string(64,'b')};
    const auto nonce=std::string(64,'c');
    auto initial=initial_update_journal(old);
    auto prepared=prepare_update(initial,target,nonce);
    auto probation=activate_update(prepared,nonce);
    auto committed=commit_update_health(probation,{nonce,target,1});
    assert(committed.active==target && committed.high_water==7 && committed.generation==4);
    for(const auto& state:{initial,prepared,probation,committed}) {
        auto bytes=serialize_update_journal(state);
        assert(serialize_update_journal(parse_update_journal(bytes))==bytes);
        for(std::size_t i=0;i<bytes.size()-1;++i)rejects([&]{parse_update_journal(bytes.substr(0,i));});
        rejects([&]{parse_update_journal(bytes+std::string(4096,' '));});
        rejects([&]{parse_update_journal(bytes.substr(0,bytes.size()-2)+",\"schema\":1}");});
        auto recovered=recover_update(parse_update_journal(bytes));
        assert(recovered.phase==UpdatePhase::Stable);
        assert(recovered.active==(state.phase==UpdatePhase::Stable?state.active:old));
        assert(recovered.high_water==state.high_water);
        assert(serialize_update_journal(recover_update(recovered))==serialize_update_journal(recovered));
    }
    for(const auto& state:{prepared,probation,committed,rollback_update(probation)})
        rejects([&]{prepare_update(state,target,nonce);});
    auto rolled=rollback_update(probation);
    auto republished=target;republished.sequence=8;republished.sha256=old.sha256;
    assert(prepare_update(rolled,republished,nonce).high_water==8); // intentional old bytes require a NEW sequence
    rejects([&]{activate_update(initial,nonce);});
    rejects([&]{activate_update(prepared,std::string(64,'d'));});
    rejects([&]{commit_update_health(prepared,{nonce,target,1});});
    rejects([&]{commit_update_health(probation,{nonce,target,0});});
    rejects([&]{commit_update_health(probation,{std::string(64,'d'),target,1});});
    for(auto wrong:{old,UpdateRevision{target.sequence,"0.2.1",target.sha256},UpdateRevision{target.sequence,target.version,old.sha256}})
        rejects([&]{commit_update_health(probation,{nonce,wrong,1});});
    auto invalid=probation;invalid.high_water=6;rejects([&]{serialize_update_journal(invalid);});
    invalid=initial;invalid.candidate=target;rejects([&]{serialize_update_journal(invalid);});
    invalid=initial;invalid.generation=max_update_sequence;rejects([&]{prepare_update(invalid,target,nonce);});
    auto document=serialize_update_journal(initial);
    for(const auto& pair:std::vector<std::pair<std::string,std::string>>{
            {"\"schema\":1","\"schema\":2"},{"\"generation\":1","\"generation\":0"},
            {"\"generation\":1","\"generation\":true"},{"\"high_water\":0","\"high_water\":-1"},
            {"\"stable\"","\"unknown\""},{"\"active\"","\"untrusted\""}}) {
        auto bad=document;bad.replace(bad.find(pair.first),pair.first.size(),pair.second);
        rejects([&]{parse_update_journal(bad);});
    }
    // Crash/failure at EVERY durable boundary. Never launch on a failed or
    // uncertain replace. Reopen disk and roll back whichever record survived.
    const std::vector<UpdateJournal> chain{initial,prepared,probation,committed};
    unsigned scenarios=0;
    for(std::size_t boundary=1;boundary<chain.size();++boundary)
        for(auto outcome:{JournalWrite::Durable,JournalWrite::NotWritten,JournalWrite::Uncertain})
            for(bool landed:{false,true}) {
                MemoryDisk disk;disk.bytes=serialize_update_journal(chain[boundary-1]);disk.outcome=outcome;disk.uncertain_landed=landed;
                bool may_act=false;
                try {persist_update_transition(disk,chain[boundary-1],chain[boundary]);may_act=true;}catch(const std::exception&){}
                assert(may_act==(outcome==JournalWrite::Durable));
                auto reopened=parse_update_journal(disk.read()),recovered=recover_update(reopened);
                assert(recovered.high_water>=chain[boundary-1].high_water);
                assert(recovered.active==(reopened.phase==UpdatePhase::Stable?reopened.active:old));
                ++scenarios;
            }
    MemoryDisk disk;disk.bytes=serialize_update_journal(prepared);
    rejects([&]{persist_update_transition(disk,initial,prepared);}); // stale concurrent caller
    disk.bytes="{truncated";rejects([&]{persist_update_transition(disk,initial,prepared);});
    disk.bytes=serialize_update_journal(probation);
    persist_update_transition(disk,probation,rolled);
    assert(parse_update_journal(disk.bytes).high_water==7);
    std::cout << "Update journal parsing, health binding, replay floor and " << scenarios << " crash-boundary cases passed\n";
}
