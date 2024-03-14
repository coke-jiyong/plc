///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#include "UmModuleExLibrary.hpp"
#include "UmModuleEx.hpp"

namespace Arp { namespace System { namespace Um
{

using Arp::System::UmModuleEx::UmModuleEx;

UmModuleExLibrary::UmModuleExLibrary(AppDomain& appDomain)
    : ModuleLibraryBase(appDomain)
{
    this->GetFactory().AddFactoryFunction(CommonTypeName<UmModuleEx>(), []() {return std::make_unique<UmModuleEx>(); });
}

extern "C" ARP_CXX_SYMBOL_EXPORT const UmModuleExLibrary& CreateUmModuleLibrary(AppDomain& appDomain)
{
    static UmModuleExLibrary instance(appDomain);
    return instance;
}

}}}

