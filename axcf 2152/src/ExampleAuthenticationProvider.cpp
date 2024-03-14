///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#include "Arp/System/Um/Commons/UmAuthenticationResult.hpp"
#include "ExampleAuthenticationProvider.hpp"
#include "UmModuleEx.hpp"
#include "UmModuleExConfig.hpp"
#include "verify.h"
#include "jwt/jwt.hpp"
#include <Arp/System/Nm/NotificationManager.hpp>
#include <Arp/System/Nm/SpecializedPayload.hpp>

namespace Arp { namespace System { namespace UmModuleEx
{

ExampleAuthenticationProvider::ExampleAuthenticationProvider(UmModuleEx& mod)
    : mod(mod)
{
    const std::string pub_key_path = "/opt/plcnext/apps/60002172000829/AuthenticationProvider/pub.key";
    const std::string token_path = "/opt/plcnext/apps/60002172000829/AuthenticationProvider/license";
    checkLicense handle(pub_key_path, token_path);
    if (!handle.init()) {
        mod.licenseCheckFail();
    }    
    if(!handle.validateHostId()) {
        mod.licenseCheckFail();
    }
    handle.clear();
}

UmAuthenticationResult ExampleAuthenticationProvider::AuthenticateUser(const String& username,
        const String& password, SessionInfo& sessionInfo)
{
    if (!mod.Started()){
        return UmAuthenticationResult::Failed;
    }
    if (!mod.UserAuthStarted()){   
        log.Debug("OTACAuthenticationProvider: License Check FAILED");
        return UmAuthenticationResult::Failed;
    }
     
    log.Debug("OTACAuthenticationProvider: License Check SUCCESS");
    
    const UserConfTag& userconf = mod.GetConfig()->userConf;
    Verify handler(password.CStr());
    if( !handler.Set_Host_IP() ) {
        log.Debug("OTACAuthenticationProvider: Error in getIP().");
        return UmAuthenticationResult::Failed;
    }
    handler.Set_Post(userconf.url.CStr());
    handler.Request();
    Json::Value root = handler.Get_Root();

    
    log.Debug("OTACAuthenticationProvider: Host Address : {0}", getIP("eth0"));
    log.Debug("OTACAuthenticationProvider: Server Address : {0}", userconf.url.CStr());
    log.Debug("OTACAuthenticationProvider:{0}", handler.Get_response());
    
    return result_check(root, username, sessionInfo);

}


UmAuthenticationResult ExampleAuthenticationProvider::result_check(Json::Value Root, const String& inputUser , SessionInfo& sessionInfo)
{
    const char * username = inputUser.CStr();
    if (Root["userId"] == username){
        if (Root["result"] == "SUCCESS"){  
            list<String> roles;       
            String Roles(Root["userRoles"].asCString());
            if (Roles.Find('|') != -1){  
                vector<string> result = split(Roles, '|');

                for(int i = 0 ; i < result.size() ; i ++) {
                    roles.push_back(result[i]);
                }
                sessionInfo.SetRoles(roles);
                for(auto i : result) {
                    i.clear();
                }
                vector<string>().swap(result);
                result.clear();
                for(auto i : roles) {
                    i.Clear();
                }
                list<String>().swap(roles);
                roles.clear();
                return UmAuthenticationResult::Success;
            }
            roles = {Roles};
            sessionInfo.SetRoles(roles);   
            std::list<String>().swap(roles);   
            roles.clear();      
            return UmAuthenticationResult::Success;
        }
        else{   
            return UmAuthenticationResult::WrongPassword;
        }
    }
    return UmAuthenticationResult::Failed;    
}


void ExampleAuthenticationProvider::OnSessionClose(SessionInfo& session)
{
    String clientIpAdress;
    String accessToken;
    log.Debug("ExampleAuthenticationProvider: session closed, id={0}, session holding lock={1}, clientIp={2}, accessToken={3}, protocolObjName={4}, user={5}",
             session.GetSecurityToken(), mod.GetLockedSession(), clientIpAdress, accessToken, session.GetProtocolObjName(), session.GetUserName());

    mod.UnlockSession(session);
}


}}} // end of namespace Arp::System::UmModuleEx




