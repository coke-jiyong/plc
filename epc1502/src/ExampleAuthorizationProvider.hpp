///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#pragma once
#include "Arp/System/Core/Arp.h"
#include "Arp/System/Um/Commons/IAuthorizationProvider.hpp"
#include "Arp/System/Commons/Threading/Mutex.hpp"
#include "Arp/System/Commons/Logging.h"

namespace Arp { namespace System { namespace UmModuleEx
{
using Arp::System::Um::Commons::IAuthorizationProvider;
using Arp::System::Um::Commons::SessionInfo;
using Arp::System::Um::Commons::Operation;
using Arp::System::Commons::Threading::Mutex;

class UmModuleEx;

class ExampleAuthorizationProvider : public IAuthorizationProvider, private Loggable<ExampleAuthorizationProvider>
{
public: // typedefs

public: // construction/destruction
    /// <summary>Constructs an <see cref="ExampleAuthorizationProvider" /> instance.</summary>
    explicit ExampleAuthorizationProvider(UmModuleEx& mod);
    /// <summary>Copy constructor.</summary>
    ExampleAuthorizationProvider(const ExampleAuthorizationProvider& arg) = default;
    /// <summary>Move constructor.</summary>
    ExampleAuthorizationProvider(ExampleAuthorizationProvider&& arg) = default;
    /// <summary>Copy-assignment operator.</summary>
    ExampleAuthorizationProvider& operator=(const ExampleAuthorizationProvider& arg) = default;
    /// <summary>Move-assignment operator.</summary>
    ExampleAuthorizationProvider& operator=(ExampleAuthorizationProvider&& arg) = default;
    /// <summary>Destructs this instance and frees all resources.</summary>
    ~ExampleAuthorizationProvider(void) = default;

public: // IAuthorizationProvider methods
    boolean SessionHasPermissionOnObject(const String& objectName, Operation operation, SessionInfo& session) override;

private:
    UmModuleEx& mod;
};

}}} // end of namespace Arp::System::UmModuleEx
