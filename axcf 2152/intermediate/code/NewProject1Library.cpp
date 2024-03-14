#include "NewProject1Library.hpp"
#include "Arp/System/Core/CommonTypeName.hxx"
#include "Arp/Plc/Commons/Meta/TypeSystem/TypeSystem.h"

namespace Arp { namespace System
{

NewProject1Library::NewProject1Library(AppDomain& appDomain)
    : MetaLibraryBase(appDomain, ARP_VERSION_CURRENT, typeDomain)
    , typeDomain(CommonTypeName<NewProject1Library>().GetNamespace())
{
    this->InitializeTypeDomain();
}

void NewProject1Library::Main(AppDomain& appDomain)
{
    SingletonBase::CreateInstance(appDomain);
}

extern "C" ARP_CXX_SYMBOL_EXPORT ILibrary& ArpDynamicLibraryMain(AppDomain& appDomain)
{
    NewProject1Library::Main(appDomain);
    return  NewProject1Library::GetInstance();
}

}} // end of namespace Arp.System
