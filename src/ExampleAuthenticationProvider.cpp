///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#include "Arp/System/Um/Commons/UmAuthenticationResult.hpp"
#include "ExampleAuthenticationProvider.hpp"
#include "UmModuleEx.hpp"
#include "UmModuleExConfig.hpp"
#include "curl.h"
#include "json.h"
#include "otacverify.h"
#include "jwt/jwt.hpp"


namespace Arp { namespace System { namespace UmModuleEx
{
ExampleAuthenticationProvider::ExampleAuthenticationProvider(UmModuleEx& _mod) 
    : mod(_mod)
{   
    using namespace jwt::params;
    const std::string pub_key_path = "/opt/plcnext/test/rsa_256/pub.key";
    const std::string token_path = "/opt/plcnext/test/testLicense";
    auto pub_key = read_from_file(pub_key_path);
    auto token = read_from_file(token_path); //license file
    jwt::jwt_object dec_obj;
    std::string hostId;
    std::string payload;
    
    try {
        dec_obj = jwt::decode(token, algorithms({"RS256"}), verify(true), secret(pub_key));
    }
    catch (const std::exception& e) {
        log.Debug("ExampleAuthenticationProvider: Error occurred={0}", e.what());
        goto end;
    }

    try{
        hostId = exec("hostid"); //OS hostID
    }
    catch(const std::exception& e){
        log.Debug("ExampleAuthenticationProvider: Error occurred={0}", e.what());
        goto end;
    }

    if (dec_obj.has_claim("hostid")) {
        try{
            payload = dec_obj.payload().get_claim_value<std::string>("hostid"); //payload hostID
        }
        catch(const exception& e){
            log.Debug("ExampleAuthenticationProvider: Error occurred={0}", e.what());
            goto end;
        }
        try{
            if (payload.compare(hostId)) {
                log.Debug("ExampleAuthenticationProvider: HostID compare failed");
                goto end;
            }
            else{
                log.Debug("ExampleAuthenticationProvider: License Check SUCCESS");
            }
        }
        catch(const exception& e){
            log.Debug("ExampleAuthenticationProvider: Error occurred={0}", e.what());
            goto end;
        }
    }
    else {
        log.Debug("ExampleAuthenticationProvider: HasClaim=false");
        goto end;
    }
    
    end:
    mod.licenseCheckFail();
}

UmAuthenticationResult ExampleAuthenticationProvider::AuthenticateUser(const String& username,
        const String& password, SessionInfo& sessionInfo)
{   
    if (!mod.Started())
    {
        return UmAuthenticationResult::Failed;
    }

    if (!mod.UserauthStarted())
    {   
        log.Debug("ExampleAuthenticationProvider: License Check Failed");
        return UmAuthenticationResult::Failed;
    }

    log.Debug("ExampleAuthenticationProvider: UserAuthStarted={0}", mod.UserauthStarted());//start log

    const UserConfTag& userconf = mod.GetConfig()->userConf;

    OtacVerify handler(password.CStr());
    handler.Otac_Set_Host_IP();
    handler.Otac_Set_Post(userconf.url.CStr());
    handler.Otac_Request();
    Json::Value Root = handler.Otac_Get_Root();

    // log.Debug("ExampleAuthenticationProvider: OTAC={0} SERVER INFO={1}",
    //           password.CStr(),userconf.url.CStr());
    
    //log.Debug("ExampleAuthenticationProvider: resonse={0}" , handler.Otac_get_response());

    if (Root["userId"] == username.CStr())
    {
        if (Root["result"] == "SUCCESS")
        {  
            std::list<String> roles;
            String Roles(Root["userRoles"].asCString());

            if (Roles.Find('|') != -1)
            {  
                vector<string> result = split(Roles, '|');

                for(int i = 0 ; i < result.size() ; i ++)
                {
                    roles.push_back(result[i]);
                }
                
                sessionInfo.SetRoles(roles);
                return UmAuthenticationResult::Success;
            }
                roles = {Roles};
                sessionInfo.SetRoles(roles);            
                return UmAuthenticationResult::Success;
        }
        else
        {   
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


std::string ExampleAuthenticationProvider::exec(const char* cmd)
{
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        log.Debug("ExampleAuthenticationProvider: excute cmd failed!(pipe)");
    }

    try {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n') {
              buffer[len - 1] = '\0';
            }
            result += buffer;  
        }
    } catch (...) {
        log.Debug("ExampleAuthenticationProvider: excute cmd failed!(fgets)");
        pclose(pipe);
    }

    pclose(pipe);
    return result;
}

std::string ExampleAuthenticationProvider::read_from_file(const std::string& path)
{
  std::string contents;
  std::ifstream is{path, std::ifstream::binary};

  if (is) {
    // get length of file:
    is.seekg (0, is.end);
    auto length = is.tellg();
    is.seekg (0, is.beg);
    contents.resize(length);

    is.read(&contents[0], length);
    if (!is) {
      is.close();
      return {};
    }
  } else {
    log.Debug("ExampleAuthenticationProvider: FILE not FOUND!!");
  }

  is.close();
  return contents;
}

}}} // end of namespace Arp::System::UmModuleEx
