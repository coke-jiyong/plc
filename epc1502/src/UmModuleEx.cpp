///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#include "Arp/System/Core/Arp.h"
#include "UmModuleEx.hpp"
#include "UmModuleExConfig.hpp"
#include "Arp/System/Um/Commons/IAuthenticationProvider.hpp"
#include "ExampleAuthenticationProvider.hpp"
#include "ExampleAuthorizationProvider.hpp"

#include <memory>

using namespace Arp::System::Commons::Threading;

namespace Arp { namespace System { namespace UmModuleEx
{

UmModuleEx::UmModuleEx(void)
{
    this->authProvider = std::make_shared<ExampleAuthenticationProvider>(*this);
    this->auzProvider = std::make_shared<ExampleAuthorizationProvider>(*this);
}

bool UmModuleEx::SetupModule(const String& settingsPath)
{
    // read module-dependent config
    this->pmodconf = UmModuleExConfig::LoadDoc(settingsPath);

    started = true;
    return true;
}
bool UmModuleEx::ResetModule()
{
    started = false;
    return true;
}

IUmAuthenticationModule::AuthenticationProviderList UmModuleEx::GetAuthenticationProviders() const
{
    AuthenticationProviderList providers;
    providers.push_back(this->authProvider);
    return providers;
}

IUmAuthorizationModule::AuthorizationProviderList UmModuleEx::GetAuthorizationProviders() const
{
    AuthorizationProviderList providers;
    providers.push_back(this->auzProvider);
    return providers;
}

bool UmModuleEx::TryLockSession(SessionInfo& session)
{
    bool ret;
    // example how to implement locking. first user with any roles
    // locks objects for writing, i.e. authorization provides saves security token as write token.
    // subsequent write attempts are only allowed for this user.
    // admin users can break/take over lock. A production implementation would also have a timeout.

    auto roles = session.GetRoles();
    bool hasAdmin = std::find(roles.cbegin(), roles.cend(), "Admin") != roles.cend();

    LockGuard lg(lockedSessionMutex);
    String wTokenVal = "1";
    if (lockedSession)
    {
        if (lockedSession == session.GetSecurityToken())   // locked by us
        {
            ret = true;
        }
        else  // locked by some other session. but admin may break lock
        {
            if (!hasAdmin)
            {
                ret = false;
            }
            else
            {
                session.SetExtensionProperty("WriteToken", wTokenVal);
                lockedSession = session.GetSecurityToken();
                ret = true;
            }
        }
    }
    else
    {
        session.SetExtensionProperty("WriteToken", wTokenVal);
        lockedSession = session.GetSecurityToken();
        ret = true;
    }
    return ret;
}

void UmModuleEx::UnlockSession(SessionInfo& session)
{
    LockGuard lg(lockedSessionMutex);
    if (lockedSession == session.GetSecurityToken())   // locked by us
    {
        lockedSession = false;
    }
}

Arp::uint32 UmModuleEx::GetLockedSession()
{
    return this->lockedSession;
}


}}}
