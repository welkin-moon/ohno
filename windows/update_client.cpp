#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <ctime>
#include "update_client.hpp"
#include "trusted_http.hpp"
#include "update_verify.hpp"
#pragma comment(lib,"bcrypt.lib")
namespace {
void require(bool ok){if(!ok)throw std::runtime_error("update transport or current approval failed");}
std::string nonce(){
    std::array<unsigned char,32> data{};require(BCryptGenRandom(nullptr,data.data(),static_cast<ULONG>(data.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0);
    constexpr char hex[]="0123456789abcdef";std::string result;for(auto c:data){result+=hex[c>>4];result+=hex[c&15];}return result;
}
struct Body{
    std::string value;
    ~Body(){if(!value.empty())SecureZeroMemory(value.data(),value.size());}
    Body(const ohno::UpdateConnection& connection,const std::string& random){
        require(ohno::update_detail::lower_hex(connection.device_id,32)&&ohno::update_detail::lower_hex(connection.device_key,64));
        value.reserve(512);value="{\"device_id\":\"";value+=connection.device_id;value+="\",\"device_key\":\"";
        value+=connection.device_key;value+="\",\"nonce\":\"";value+=random;value+="\"}";
    }
};
struct Download {
    std::wstring path;HANDLE file=INVALID_HANDLE_VALUE;
    explicit Download(const std::wstring& root){
        const auto random=nonce();path=root+L"\\download-"+std::wstring(random.begin(),random.end())+L".tmp";
        // Uncommitted download bytes do not need a disk flush per network
        // fragment. finish() still flushes the complete file before validation
        // and durable staging; interrupted downloads are never executable.
        file=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        require(file!=INVALID_HANDLE_VALUE);
    }
    ~Download(){if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);if(!path.empty())DeleteFileW(path.c_str());}
    void finish(){require(FlushFileBuffers(file)!=FALSE);CloseHandle(file);file=INVALID_HANDLE_VALUE;}
};
}
namespace ohno {
std::optional<StagedUpdate> fetch_staged_update(WindowsUpdateJournal& storage,const UpdateConnection& connection,
    const UpdateJournal& current,HANDLE stop){
    transaction_detail::validate(current);require(current.phase==UpdatePhase::Stable);
    if(connection.release_public_key.empty())return std::nullopt; // never learn a key from an offer
    Body offer_body(connection,nonce());
    TrustedPost offer_request{connection.server,connection.certificate_pem,L"/api/device/update/offer",offer_body.value};
    offer_request.max_response=4096;offer_request.stop_event=stop;
    const auto response=trusted_post(offer_request);
    require(response.failure==TrustedHttpFailure::None);
    if(response.status==404||response.status==403)return std::nullopt;
    require(response.status==200);
    const auto manifest=verify_update_offer(response.body,connection.release_public_key,current.high_water,updater_protocol_version,
        static_cast<std::uint64_t>(std::time(nullptr)));
    Download package(storage.directory_path());
    Body package_body(connection,nonce());
    const auto path=update_package_path(manifest);
    TrustedPost request{connection.server,connection.certificate_pem,std::wstring(path.begin(),path.end()),package_body.value};
    request.binary=true;request.max_response=static_cast<std::size_t>(manifest.size);request.timeout_ms=300000;request.stop_event=stop;
    const auto downloaded=trusted_post(request,[&](const char* data,std::size_t count){
        DWORD wrote=0;return WriteFile(package.file,data,static_cast<DWORD>(count),&wrote,nullptr)!=FALSE&&wrote==count;
    });
    require(downloaded.failure==TrustedHttpFailure::None&&downloaded.status==200);package.finish();
    // Reverify the signed offer and its freshness after potentially long I/O.
    auto revision=stage_update_payload(storage,response.body,connection.release_public_key,package.path,current.high_water,
        static_cast<std::uint64_t>(std::time(nullptr)),stop);
    return StagedUpdate{revision,manifest,response.body};
}
bool authorize_staged_update(const UpdateConnection& connection,const StagedUpdate& update,HANDLE stop){
    try {
        const auto now=static_cast<std::uint64_t>(std::time(nullptr));
        require(now>0&&update.manifest.expires_at>now&&update.manifest.issued_at<=now+300);
        require(update.revision.sequence==update.manifest.sequence&&update.revision.sha256==update.manifest.sha256&&update.revision.version==update.manifest.version);
        const auto random=nonce();Body body(connection,random);body.value.pop_back();
        body.value+=",\"sequence\":";body.value+=std::to_string(update.revision.sequence);body.value+=",\"sha256\":\"";body.value+=update.revision.sha256;body.value+="\"}";
        TrustedPost request{connection.server,connection.certificate_pem,L"/api/device/update/authorize",body.value};request.stop_event=stop;
        const auto response=trusted_post(request);
        if(response.failure!=TrustedHttpFailure::None||response.status!=200)return false;
        const auto value=ohno_json::parse(response.body);
        if(value.type!=ohno_json::value::kind::object||value.fields.size()!=7)return false;
        const auto& authorized=value.at("authorized");
        if(authorized.type!=ohno_json::value::kind::boolean||!authorized.boolean||
            update_detail::text(value,"nonce")!=random||update_detail::text(value,"device_id")!=connection.device_id||
            update_detail::text(value,"sha256")!=update.revision.sha256||
            update_detail::integer(value,"sequence",1,max_update_sequence)!=update.revision.sequence)return false;
        const auto issued=update_detail::integer(value,"authorized_at",1,max_update_timestamp);
        const auto expires=update_detail::integer(value,"expires_at",1,max_update_timestamp);
        const auto received=static_cast<std::uint64_t>(std::time(nullptr));
        return expires>issued&&expires-issued==120&&received>0&&issued<=received+30&&received<expires+30;
    }catch(...){return false;}
}
}
