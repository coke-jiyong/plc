#include "verify.h"

Verify::Verify(const char * _otac)
{
    ver_json["otac"] = _otac;
    ver_json["pcDeviceId"] = "127.0.0.1";
    ver_json["systemId"] = "1";
    ver_json["apiKey"] = "PLC_567052367261557962726962304c69424b374546433867766b4a314a33715851";

}
Verify::Verify()
{
    //cout << "input parameter(otac)"<< endl;
    return;
}

bool Verify::Set_Host_IP()
{
    string ip = getIP("lan1");
    if(ip == " "){
        return false;
    }
    ver_json["plcDeviceId"] = ip;   
    return true;
}

void Verify::Set_Post(const char* url)
{
    if(!curl_handle.init()) {
        return;
    }
    curl_handle.set_header_content("Content-Type","application/json");
    JsonStr = writer.write(ver_json);
    curl_handle.set_post(JsonStr);
    curl_handle.set_server_info(url);
}

void Verify::Request()
{
    if (curl_handle.request()){
        return ;
    }
    response = curl_handle.response();
    Json::Reader reader;
    reader.parse(response, root);
}

Json::Value Verify::Get_Root(){ return root ; }

std::string Verify::Get_response(){ return response ; }

vector<string> split(string input, char dlim)
{
	vector<string> result;	
	stringstream ss;		
	string stringBuffer;	
	ss.str(input);			
	
    
	while (getline(ss, stringBuffer, dlim))	
	{
		result.push_back(stringBuffer);
	}

	return result;
}


string getIP(string interface){
    string cmd = "ifconfig " + interface; 
    string result = exec(cmd.c_str());
    return ipPaser(result);
}

string exec(const char* cmd)
{
    char buffer[128];
    string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        return NULL;
    }
    try {
        int i = 1;
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n') {
              buffer[len - 1] = '\n';
            }
            result += buffer;  
        }
    } catch (...) {
        pclose(pipe);
        return NULL;
    }
    pclose(pipe);
    return result;
}

string ipPaser(string str)
{
    size_t nPos = str.find("inet");
    if( nPos != string::npos ) { 
	    string subtext = str.substr(nPos);
        istringstream ss(subtext);
        string buff;
        for(int i = 0 ; i < 2; i ++)
            getline(ss, buff, ' ');
        return buff;
    }

    return " ";   
}

