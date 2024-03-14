///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#pragma once
#include "Arp/System/Core/Arp.h"
#include "Arp/System/Um/Commons/IAuthenticationProvider.hpp"
#include "Arp/System/Commons/Logging.h"
#include "curl.h"
#include "json.h"
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <fstream>
using namespace std;
namespace Arp { namespace System { namespace UmModuleEx
{
using Arp::System::Um::Commons::IAuthenticationProvider;
using Arp::System::Um::Commons::UmAuthenticationResult;
using Arp::System::Um::Commons::SessionInfo;

class UmModuleEx;

class ExampleAuthenticationProvider : public IAuthenticationProvider, private Loggable<ExampleAuthenticationProvider>
{
public: // typedefs

public: // construction/destruction
    /// <summary>Constructs an <see cref="ExampeAuthenticationProvider" /> instance.</summary>
    explicit ExampleAuthenticationProvider(UmModuleEx& mod);
    /// <summary>Copy constructor.</summary>
    ExampleAuthenticationProvider(const ExampleAuthenticationProvider& arg) = default;
    /// <summary>Move constructor.</summary>
    ExampleAuthenticationProvider(ExampleAuthenticationProvider&& arg) = default;
    /// <summary>Copy-assignment operator.</summary>
    ExampleAuthenticationProvider& operator=(const ExampleAuthenticationProvider& arg) = default;
    /// <summary>Move-assignment operator.</summary>
    ExampleAuthenticationProvider& operator=(ExampleAuthenticationProvider&& arg) = default;
    /// <summary>Destructs this instance and frees all resources.</summary>
    ~ExampleAuthenticationProvider(void) override = default;
    /// <summary>otac result check.</summary>
    UmAuthenticationResult result_check(Json::Value root, const String& inputUser , SessionInfo& sessionInfo);


    

public: // IAuthenticationProvider methods
    UmAuthenticationResult AuthenticateUser(const String& username, const String& password, SessionInfo& sessionInfo) override;
    void OnSessionClose(SessionInfo& session) override;

private:
    UmModuleEx& mod;
};




///////////////////////////////////////////////////////////////////////////////
// inline methods of class ExampeAuthenticationProvider

}}} // end of namespace Arp::System::UmModuleEx
