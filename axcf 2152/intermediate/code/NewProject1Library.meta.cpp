#include "Arp/System/Core/Arp.h"
#include "Arp/Plc/Commons/Meta/TypeSystem/TypeSystem.h"
#include "NewProject1Library.hpp"

namespace Arp { namespace System
{

using namespace Arp::Plc::Commons::Meta;

    void NewProject1Library::InitializeTypeDomain()
    {
        this->typeDomain.AddTypeDefinitions
        (
            // Begin TypeDefinitions
            {
            }
            // End TypeDefinitions
        );
    }

}} // end of namespace Arp.System

