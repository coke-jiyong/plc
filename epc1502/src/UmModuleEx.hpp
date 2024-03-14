///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#pragma once
#include "Arp/System/Core/Arp.h"
#include "Arp/System/Commons/Threading/Thread.hpp"
#include "Arp/System/Um/Commons/IAuthenticationProvider.hpp"
#include "Arp/System/Um/Commons/Modules/UmModuleBase.hpp"
#include "Arp/System/Um/Commons/Modules/IUmAuthenticationModule.hpp"
#include "Arp/System/Um/Commons/Modules/IUmAuthorizationModule.hpp"

namespace Arp { namespace System { namespace UmModuleEx
{
// fwd declarations
class UmModuleExConfig;

using namespace Arp::System::Um::Commons;
using Arp::System::Commons::Threading::Mutex;
using namespace Arp::System::Um::Commons::Modules;

/// <summary>Minimal example for a UserManager loadable module, which registers a custom authentication
/// provider.</summary>
class UmModuleEx : public UmModuleBase,
    public IUmAuthenticationModule, public IUmAuthorizationModule
{
public: // typedefs/usings

public: // construction/destruction
    /// <summary>Constructs a <see cref="UmModuleEx" /> instance.</summary>
    UmModuleEx(void);
    /// <summary>Copy constructor.</summary>
    UmModuleEx(const UmModuleEx& arg) = default;
    /// <summary>Move constructor.</summary>
    UmModuleEx(UmModuleEx&& arg) = default;
    /// <summary>Copy-assignment operator.</summary>
    UmModuleEx& operator=(const UmModuleEx& arg) = default;
    /// <summary>Move-assignment operator.</summary>
    UmModuleEx& operator=(UmModuleEx&& arg) = default;
    /// <summary>Destructs this instance and frees all resources.</summary>
    ~UmModuleEx(void) override = default;

public: // setter/getter operations
    std::shared_ptr<UmModuleExConfig> GetConfig() const
    {
        return pmodconf;
    }

public: // IUmModule operations
    bool SetupModule(const String& settingsPath) override;
    bool ResetModule() override;
    
    // IUmAuthenticationModule
    IUmAuthenticationModule::AuthenticationProviderList GetAuthenticationProviders() const override;
    // IUmAuthorizationModule
    IUmAuthorizationModule::AuthorizationProviderList GetAuthorizationProviders() const override;

public: // operations
    bool Started() const
    {
        return started;
    }
    bool UserauthStarted()
    {
        return UserAuthentication;
    }
    void licenseCheckFail()
    {
        UserAuthentication = false;
    }
    
    bool TryLockSession(SessionInfo& session);
    void UnlockSession(SessionInfo& session);
    Arp::uint32 GetLockedSession();

private: // fields
    bool started = false;
    bool UserAuthentication = true;
    std::shared_ptr<UmModuleExConfig> pmodconf;
    std::shared_ptr<IAuthenticationProvider> authProvider;
    std::shared_ptr<IAuthorizationProvider> auzProvider;

    Arp::uint32 lockedSession = 0;
    Mutex lockedSessionMutex;
};

}}}
