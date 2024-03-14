///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#include "Arp/System/Core/Arp.h"
#include "UmModuleExConfig.hpp"

namespace Arp { namespace System { namespace UmModuleEx
{

using namespace Arp::System::Commons::Xml;

std::shared_ptr<UmModuleExConfig> UmModuleExConfig::LoadDoc(const String& moduleConfigPath)
{
    ModuleConfigDocument configDoc;
    configDoc.Load(moduleConfigPath);
    UmModuleExConfig& modconf = static_cast<UmModuleExConfig&>(configDoc.GetContent());
    return std::make_shared<UmModuleExConfig>(modconf);
}
}}}
