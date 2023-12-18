#include "ExampleAuthenticationProvider.hpp"

class OtacVerify
{
    private:
        int getIP(char*, int);
        Json::Value ver_json;
        CURL_Handler curl_handle;
        Json::StyledWriter writer;
        string JsonStr;
        string response;
        Json::Value root;

    public:
        OtacVerify(const char * _otac);
        OtacVerify();
        void Otac_Set_Host_IP();
        void Otac_Set_Post(const char* url);
        void Otac_Request();
        Json::Value Otac_Get_Root();
        std::string Otac_get_response();
};

vector<string> split(string input, char dlim);