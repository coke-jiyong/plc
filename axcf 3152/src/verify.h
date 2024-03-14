#ifndef VERIFY_H

#include "ExampleAuthenticationProvider.hpp"
using namespace std;
class Verify
{
    private:
        Json::Value ver_json;
        CURL_Handler curl_handle;
        Json::StyledWriter writer;
        string JsonStr;
        string response;
        Json::Value root;

    public:
        Verify(const char * _otac);
        Verify();
        bool Set_Host_IP();
        void Set_Post(const char* url);
        void Request();
        Json::Value Get_Root();
        std::string Get_response();
};

string getIP(string interface);
vector<string> split(string input, char dlim);
string ipPaser(string str);
string exec(const char* cmd);
#endif