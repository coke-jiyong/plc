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

namespace Arp { namespace System { namespace UmModuleEx
{

ExampleAuthenticationProvider::ExampleAuthenticationProvider(UmModuleEx& mod)
    : mod(mod)
{
}

UmAuthenticationResult ExampleAuthenticationProvider::AuthenticateUser(const String& username,
        const String& password, SessionInfo& sessionInfo)
{
    if (!mod.Started())
    {
        return UmAuthenticationResult::Failed;
    }
    const UserConfTag& userconf = mod.GetConfig()->userConf;
    Verify handler(password.CStr());
    if( !handler.Set_Host_IP() ) {
        log.Debug("OTACAuthenticationProvider: Error in getIP().");
        return UmAuthenticationResult::Failed;
    }
    handler.Set_Post(userconf.url.CStr());
    handler.Request();
    Json::Value root = handler.Get_Root();

    log.Debug("OTACAuthenticationProvider: Host Address : {0}", getIP("lan1"));
    log.Debug("OTACAuthenticationProvider: Server Address : {0}", userconf.url.CStr());
    log.Debug("OTACAuthenticationProvider:{0}", handler.Get_response());
    
    return result_check(root, username, sessionInfo);
}

UmAuthenticationResult ExampleAuthenticationProvider::result_check(Json::Value root, const String& inputUser , SessionInfo& sessionInfo)
{   
    const char * username = inputUser.CStr();
    if (root["userId"] == username)
     {
          if (root["result"] == "SUCCESS")
         {  
             string Role(root["userRoles"].asCString());
             std::list<String> roles;
             if (Role.find('|') != -1){
                std::vector<string> v = split(Role, '|');
                for (int i = 0 ; i < v.size() ; i ++)
                    roles.push_back(v[i]);
                sessionInfo.SetRoles(roles);
                for(auto i : roles )
                    i.Clear();
                roles.clear();
                for(auto i : v)
                    i.clear();
                v.clear();
                return UmAuthenticationResult::Success;
             }
             roles = {Role};
             sessionInfo.SetRoles(roles);            
             roles.clear();
             return UmAuthenticationResult::Success;
         }
         else {   
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

