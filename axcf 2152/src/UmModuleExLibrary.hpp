///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#pragma once
#include "Arp/System/Core/Arp.h"
#include "Arp/System/Commons/Extensibility/ModuleLibraryBase.hxx"
#include "Arp/System/Um/Commons/Modules/IUmModule.hpp"
#include "Arp/System/Um/Commons/Modules/UmModuleBase.hpp"

namespace Arp { namespace System { namespace Um
{
using namespace Arp::System::Um::Commons::Modules;

class UmModuleExLibrary: public Arp::System::Commons::Extensibility::ModuleLibraryBase<Arp::System::Um::Commons::Modules::IUmModule>

{
public: // typedefs/usings

public: // construction/destruction
    /// <summary>Constructs an <see cref="UmModuleExLibrary" /> instance.</summary>
    explicit UmModuleExLibrary(AppDomain& appDomain);
    /// <summary>Copy constructor.</summary>
    UmModuleExLibrary(const UmModuleExLibrary& arg) = delete;
    /// <summary>Move constructor.</summary>
    UmModuleExLibrary(UmModuleExLibrary&& arg) = delete;
    /// <summary>Copy-assignment operator.</summary>
    UmModuleExLibrary& operator=(const UmModuleExLibrary& arg) = delete;
    /// <summary>Move-assignment operator.</summary>
    UmModuleExLibrary& operator=(UmModuleExLibrary&& arg) = delete;
    /// <summary>Destructs this instance and frees all resources.</summary>
    ~UmModuleExLibrary(void) override = default;

};

}}}

