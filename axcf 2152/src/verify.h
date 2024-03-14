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

using namespace jwt::params;
class checkLicense {
public:
    checkLicense(const std::string _pub_key_path ,const std::string _token_path)
    : pub_key_path(_pub_key_path), token_path(_token_path) 
    {
    }
    bool init();
    bool validateHostId();
    void clear();

private:
    jwt::jwt_object dec_obj;
    std::string hostId;
    const std::string pub_key_path;
    const std::string token_path;
    string payload;
    std::vector<string> v;
};

vector<string> split(string input, char dlim);
std::string exec(const char* cmd);
std::string read_from_file(const std::string& path);
string getIP(string interface);
string ipPaser(string str);