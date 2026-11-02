// Read-only diagnostic for the disposable installed-service CI fixture.
// Never prints credentials, headers, bodies, private keys or exception contents.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ctime>
#include <iostream>
#include "../windows/update_configuration.hpp"
#include "../windows/trusted_http.hpp"
#include "../windows/update_verify.hpp"
int main(){
    const char* stage="configuration";
    try{
        auto config=ohno::installed_update_connection();
        struct Wipe{std::string& value;~Wipe(){if(!value.empty())SecureZeroMemory(value.data(),value.size());}} wipe{config.device_key};
        if(config.release_public_key!=ohno::installed_release_key())return 2;
        std::cout<<"Installed update configuration lengths "<<config.server.size()<<" "<<config.certificate_pem.size()<<" "
            <<config.release_public_key.size()<<" "<<config.device_id.size()<<" "<<config.device_key.size()<<std::endl;
        if(!ohno::update_detail::lower_hex(config.device_id,32)||!ohno::update_detail::lower_hex(config.device_key,64))return 3;
        std::string body;body.reserve(512);Wipe wipe_body{body};
        body="{\"device_id\":\"";body+=config.device_id;body+="\",\"device_key\":\"";body+=config.device_key;
        body+="\",\"nonce\":\"";body+=std::string(64,'a');body+="\"}";
        stage="offer transport";
        ohno::TrustedPost request{config.server,config.certificate_pem,L"/api/device/update/offer",body};request.max_response=4096;
        const auto response=ohno::trusted_post(request);
        std::cout<<"Installed offer failure/status "<<static_cast<unsigned>(response.failure)<<" "<<response.status<<std::endl;
        if(response.failure!=ohno::TrustedHttpFailure::None||response.status!=200)return 4;
        stage="offer signature";
        const auto manifest=ohno::verify_update_offer(response.body,config.release_public_key,0,ohno::updater_protocol_version,
            static_cast<std::uint64_t>(std::time(nullptr)));
        std::cout<<"Installed signed offer sequence/bytes "<<manifest.sequence<<" "<<manifest.size<<std::endl;
        return 0;
    }catch(...){std::cout<<"Installed update probe failed at "<<stage<<std::endl;return 1;}
}
