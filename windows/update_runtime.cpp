#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include "update_runtime.hpp"
#include "worker_process.hpp"
namespace {
std::string nonce(){std::array<unsigned char,32> data{};
    if(BCryptGenRandom(nullptr,data.data(),static_cast<ULONG>(data.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("health nonce failed");
    std::string result;constexpr char hex[]="0123456789abcdef";for(auto ch:data){result+=hex[ch>>4];result+=hex[ch&15];}return result;}
bool stopping(HANDLE stop){return WaitForSingleObject(stop,0)!=WAIT_TIMEOUT;}
void checkpoint(const ohno::UpdateRuntimeOptions& options,unsigned point){
#ifdef OHNO_UPDATE_IO_TESTING
    if(options.checkpoint)options.checkpoint(point);
#else
    (void)options;(void)point;
#endif
}
struct Wipe {ohno::UpdateConnection& c;~Wipe(){if(!c.device_key.empty())SecureZeroMemory(c.device_key.data(),c.device_key.size());}};
}
namespace ohno {
void run_update_runtime(const std::wstring& root,const std::string& key,HANDLE stop,
    const std::function<UpdateConnection()>& connection,const UpdateRuntimeOptions& options) {
    if(!stop||!options.poll_ms||!options.health_timeout_ms||!options.restart_delay_ms)throw std::runtime_error("invalid runtime options");
    WindowsUpdateJournal storage(root);auto state=parse_update_journal(storage.read());
    auto persist=[&](const UpdateJournal& next){persist_update_transition(storage,state,next);state=next;};
    if(state.phase!=UpdatePhase::Stable){persist(recover_update(state));checkpoint(options,1);}
    std::unique_ptr<WorkerProcess> worker;
    auto drain=[&]{if(worker&&!worker->stop())throw std::runtime_error("worker tree did not drain; no next version may start");worker.reset();};
    auto launch=[&](const UpdateRevision& revision,const std::string& transaction){
        worker=std::make_unique<WorkerProcess>();worker->start(storage,revision,key,transaction,stop);
        UpdateHealth proof;return worker->healthy(stop,options.health_timeout_ms,proof);
    };
    unsigned restarts=0;ULONGLONG restart_window=GetTickCount64(),next_poll=0;
    while(!stopping(stop)){
        if(!worker||!worker->running()){
            drain();
            if(GetTickCount64()-restart_window>60000){restarts=0;restart_window=GetTickCount64();}
            if(++restarts>3)throw std::runtime_error("worker repeatedly failed; standard service recovery required");
            bool healthy=false;try{healthy=launch(state.active,nonce());}catch(...){if(stopping(stop))break;throw;}
            if(!healthy){drain();if(WaitForSingleObject(stop,options.restart_delay_ms)!=WAIT_TIMEOUT)break;continue;}
            checkpoint(options,2);next_poll=0;
        }
        if(stopping(stop))break;
        if(GetTickCount64()>=next_poll){
            next_poll=GetTickCount64()+options.poll_ms;
            ULONGLONG authorized_until=0;std::optional<StagedUpdate> offered;UpdateConnection current;Wipe wipe{current};
            // Transport rejection/offline is not a worker failure. Keep serving
            // current policy, and retry later without changing durable state.
            try{
                current=connection();
                if(current.release_public_key!=key)throw std::runtime_error("installation release key changed");
                offered=fetch_staged_update(storage,current,state,stop);
                if(offered&&!stopping(stop)){
                    verify_staged_payload(storage,offered->revision,key,stop);
                    checkpoint(options,3);
                    if(!authorize_staged_update(current,*offered,stop))offered.reset();
                    else authorized_until=GetTickCount64()+20000;
                }
            }catch(...){offered.reset();}
            if(offered&&!stopping(stop)){
                // Fresh authorization immediately precedes durable prepare. Do
                // not wrap persistence in a retry: uncertain writes must exit.
                persist(prepare_update(state,offered->revision,nonce()));checkpoint(options,4);
                drain(); // old worker and its TUN are gone before switch
                if(stopping(stop)){persist(rollback_update(state));break;}
                persist(activate_update(state,state.transaction));checkpoint(options,5);
                bool healthy=false;UpdateHealth proof;
                try{
                    worker=std::make_unique<WorkerProcess>();worker->start(storage,state.active,key,state.transaction,stop,authorized_until);checkpoint(options,6);
                    healthy=worker->healthy(stop,options.health_timeout_ms,proof);
                }catch(...){healthy=false;}
                if(healthy&&!stopping(stop)){
                    checkpoint(options,7);
                    if(stopping(stop)){drain();persist(rollback_update(state));break;}
                    persist(commit_update_health(state,proof));checkpoint(options,8);
                    restarts=0;restart_window=GetTickCount64();
                }else{
                    drain();persist(rollback_update(state));checkpoint(options,9);
                    // Rollback retains high-water. No repeated bad build or
                    // old-worker restart if STOP/uninstall is already pending.
                }
            }
            checkpoint(options,14);
        }
        if(!worker)continue;
        if(WaitForSingleObject(stop,100)!=WAIT_TIMEOUT)break;
    }
    drain();
    if(state.phase!=UpdatePhase::Stable)persist(rollback_update(state));
}
}
