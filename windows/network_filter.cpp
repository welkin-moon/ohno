#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <rpc.h>
#include <algorithm>
#include "network_filter.hpp"
#pragma comment(lib,"fwpuclnt.lib")
#pragma comment(lib,"rpcrt4.lib")
NetworkFilter::NetworkFilter(){
    FWPM_SESSION0 session{};session.flags=FWPM_SESSION_FLAG_DYNAMIC;
    if(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&session,&engine_)!=ERROR_SUCCESS){engine_=nullptr;return;}
    if(UuidCreate(&sublayer_)!=RPC_S_OK){FwpmEngineClose0(engine_);engine_=nullptr;return;}
    FWPM_SUBLAYER0 sub{};sub.subLayerKey=sublayer_;sub.displayData.name=const_cast<wchar_t*>(L"ohno experimental outbound rules");sub.weight=0x100;
    if(FwpmSubLayerAdd0(engine_,&sub,nullptr)!=ERROR_SUCCESS){FwpmEngineClose0(engine_);engine_=nullptr;}
}
NetworkFilter::~NetworkFilter(){if(engine_)FwpmEngineClose0(engine_);}
bool NetworkFilter::add(const std::wstring& path,Item& item){
    FWP_BYTE_BLOB* id=nullptr;if(FwpmGetAppIdFromFileName0(path.c_str(),&id)!=ERROR_SUCCESS)return false;
    FWPM_FILTER_CONDITION0 condition{};condition.fieldKey=FWPM_CONDITION_ALE_APP_ID;condition.matchType=FWP_MATCH_EQUAL;condition.conditionValue.type=FWP_BYTE_BLOB_TYPE;condition.conditionValue.byteBlob=id;
    FWPM_FILTER0 f{};f.displayData.name=const_cast<wchar_t*>(L"ohno untrusted application outbound");f.subLayerKey=sublayer_;f.weight.type=FWP_EMPTY;f.action.type=FWP_ACTION_BLOCK;f.numFilterConditions=1;f.filterCondition=&condition;
    f.layerKey=FWPM_LAYER_ALE_AUTH_CONNECT_V4;DWORD result=FwpmFilterAdd0(engine_,&f,nullptr,&item.v4);
    if(result==ERROR_SUCCESS){f.layerKey=FWPM_LAYER_ALE_AUTH_CONNECT_V6;result=FwpmFilterAdd0(engine_,&f,nullptr,&item.v6);if(result!=ERROR_SUCCESS)FwpmFilterDeleteById0(engine_,item.v4);}
    FwpmFreeMemory0(reinterpret_cast<void**>(&id));item.blocked=result==ERROR_SUCCESS;return item.blocked;
}
void NetworkFilter::remove(Item& item){if(item.blocked){FwpmFilterDeleteById0(engine_,item.v4);FwpmFilterDeleteById0(engine_,item.v6);item.blocked=false;}}
bool NetworkFilter::register_untrusted(const std::wstring& path,const std::string& hash){
    if(!engine_||paused_)return false;
    auto it=items_.find(path);if(it!=items_.end()&&it->second.hash!=hash){remove(it->second);items_.erase(it);it=items_.end();}
    if(it==items_.end())it=items_.emplace(path,Item{hash}).first;
    return it->second.blocked||add(path,it->second);
}
void NetworkFilter::apply_grants(const std::vector<std::string>& hashes){
    if(!engine_||paused_)return;
    for(auto& entry:items_){auto& item=entry.second;bool granted=std::find(hashes.begin(),hashes.end(),item.hash)!=hashes.end();if(granted)remove(item);else if(!item.blocked)add(entry.first,item);}
}
void NetworkFilter::set_paused(bool paused){
    if(!engine_||paused_==paused)return;paused_=paused;
    for(auto& entry:items_){if(paused_)remove(entry.second);else if(!entry.second.blocked)add(entry.first,entry.second);}
}
