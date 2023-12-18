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
#define IP_SIZE 16



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
    //ExampleAuthenticationProvider(UmModuleEx& mod, SessionInfo& _sessionInfo);
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
    /// <summary>excute cmd and return result.</summary>
    std::string exec(const char* cmd);
    /// <summary>read file of path.</summary>
    std::string read_from_file(const std::string& path);

public: // IAuthenticationProvider methods
    UmAuthenticationResult AuthenticateUser(const String& username, const String& password, SessionInfo& sessionInfo) override;
    void OnSessionClose(SessionInfo& session) override;

private:
    UmModuleEx& mod;
};





///////////////////////////////////////////////////////////////////////////////
// inline methods of class ExampeAuthenticationProvider

}}} // end of namespace Arp::System::UmModuleEx
