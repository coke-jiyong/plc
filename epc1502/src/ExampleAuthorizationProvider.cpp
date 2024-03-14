///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#include "ExampleAuthorizationProvider.hpp"
#include "UmModuleEx.hpp"
#include <algorithm>
#include "Arp/System/Commons/Threading/LockGuard.hpp"
#include "Arp/System/Um/Commons/SessionInfo.hpp"

namespace Arp { namespace System { namespace UmModuleEx
{

ExampleAuthorizationProvider::ExampleAuthorizationProvider(UmModuleEx& mod)
    : mod(mod)
{
}

boolean ExampleAuthorizationProvider::SessionHasPermissionOnObject(const String& objectName,
        Operation operation, SessionInfo& session)
{
    bool ret = true;
    if (!mod.Started())
    {
        return ret;
    }

    if (objectName == String("arp.test.testobject") && operation == Operation::Call)
    {
        // example how to disallow calls on a particular object. Also used in unit test.
        ret = false;
    }
    if (objectName == String("arp.services.wbm/modules/Fwm") && operation == Operation::Call)
    {
        // this example allows easy testing on target: if module is loaded, FirewallManager site in WBM is not shown
        ret = false;
    }
    if (operation == Operation::WriteValue)
    {
        uint32 oldLockedSession = mod.GetLockedSession();
        ret = mod.TryLockSession(session);
        log.Debug("ExampleAuthorizationProvider: writeValue request on object {0}, session id={1}, TryLockSession result: {2}, old session holding lock={3}, protocolObjName={4}, user={5}",
                 objectName, session.GetSecurityToken(), ret, oldLockedSession, session.GetProtocolObjName(), session.GetUserName());
    }

    return ret;
}


}}} // end of namespace Arp::System::UmModuleEx
