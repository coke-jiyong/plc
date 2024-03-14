#pragma once
#include "Arp/System/Core/Arp.h"
#include "Arp/System/Core/AppDomain.hpp"
#include "Arp/System/Core/Singleton.hxx"
#include "Arp/System/Core/Library.h"
#include "Arp/Plc/Commons/Meta/MetaLibraryBase.hpp"
#include "Arp/Plc/Commons/Meta/TypeSystem/TypeDomain.hpp"

namespace Arp { namespace System
{

using namespace Arp::System::Acf;
using namespace Arp::Plc::Commons::Meta;
using namespace Arp::Plc::Commons::Meta::TypeSystem;

class NewProject1Library : public MetaLibraryBase, public Singleton<NewProject1Library>
{
public: // typedefs
    typedef Singleton<NewProject1Library> SingletonBase;

public: // construction/destruction
    NewProject1Library(AppDomain& appDomain);
    virtual ~NewProject1Library() = default;

public: // static operations (called through reflection)
    static void Main(AppDomain& appDomain);

private: // methods
    void InitializeTypeDomain();

private: // deleted methods
    NewProject1Library(const NewProject1Library& arg) = delete;
    NewProject1Library& operator= (const NewProject1Library& arg) = delete;

private:  // fields
    TypeDomain typeDomain;
};

extern "C" ARP_CXX_SYMBOL_EXPORT ILibrary& ArpDynamicLibraryMain(AppDomain& appDomain);

///////////////////////////////////////////////////////////////////////////////
// inline methods of class NewProject1Library

}} // end of namespace Arp.System
