///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////

#pragma once
#include "Arp/System/Core/Arp.h"
#include "Arp/System/Commons/Xml/XmlConfigDocument.hpp"

namespace Arp { namespace System { namespace UmModuleEx
{

using namespace Arp::System::Commons::Xml;

class UserConfTag : public IXmlSerializable
{
public:
    UserConfTag() = default;
    ~UserConfTag() override = default;

public: // IXmlSerializable operations
    void ReadXml(XmlReader& reader, XmlSerializationContext& ) override
    {

        if (reader.GetElementLocalName() == "UserConf")
        {
            // this->userName = reader.GetAttributeValue<String>("UserName");
            // this->key = reader.GetAttributeValue<String>("Key");
            // this->primaryRole = reader.GetAttributeValue<String>("PrimaryRole");
            this->url = reader.GetAttributeValue<String>("url");
            reader.ReadEndElement();
        }
       
    }
        

    
    void WriteXml(XmlWriter&, XmlSerializationContext& ) override
    {
        // write functionality not required here
    };

public: //properties

    // String userName;
    // String key;
    // String primaryRole;
    String url;
};


class UmModuleExConfig : public IXmlSerializable
{
public:
    UmModuleExConfig() = default;
    UmModuleExConfig(const UmModuleExConfig&) = default;
    UmModuleExConfig& operator=(const UmModuleExConfig&) = default;
    ~UmModuleExConfig(void) override = default;

public: // IXmlSerializable operations
    void ReadXml(XmlReader& reader, XmlSerializationContext& context) override
    {

        if (reader.IsEmptyElement())
        {
            return;
        }
        while (reader.TryReadStartElement())
        {
            if (reader.GetElementLocalName() == "UserConf")
            {
                userConf.ReadXml(reader, context);
            }
            else
            {
                reader.ReadEndElement();
            }
        }

    }
    void WriteXml(XmlWriter&, XmlSerializationContext&) override
    {
        // write functionality not required here
    };

    static std::shared_ptr<UmModuleExConfig> LoadDoc(const String& moduleConfigPath);

public: // fields
    UserConfTag userConf;
};

class ModuleConfigDocument : public XmlConfigDocument
{
public: // construction/destruction
    ModuleConfigDocument() :
        XmlConfigDocument("UmModuleConfigDocument", this->contentVal)
    {
    }

private: // fields
    UmModuleExConfig  contentVal;
};
}}}

