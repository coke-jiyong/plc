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
    string ip = getIP("eth0");
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


std::string exec(const char* cmd)
{
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        //log.Debug("OTACAuthenticationProvider: excute cmd failed!(pipe)");
    }

    try {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n') {
              buffer[len - 1] = '\0';
            }
            result += buffer;  
        }
    } catch (...) {
        //log.Debug("OTACAuthenticationProvider: excute cmd failed!(fgets)");
        pclose(pipe);
    }

    pclose(pipe);
    return result;
}

std::string read_from_file(const std::string& path)
{
  std::string contents;
  std::ifstream is{path, std::ifstream::binary};

  if (is) {
    // get length of file:
    is.seekg (0, is.end);
    auto length = is.tellg();
    is.seekg (0, is.beg);
    contents.resize(length);

    is.read(&contents[0], length);
    if (!is) {
      is.close();
      return {};
    }
  } else {
    //log.Debug("OTACAuthenticationProvider: FILE not FOUND");
  }

  is.close();
  return contents;
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

string getIP(string interface){
    string cmd = "ifconfig " + interface; 
    string result = exec(cmd.c_str());
    return ipPaser(result);
}

bool checkLicense::validateHostId()
{
    if (dec_obj.has_claim("hostId")) {
        try{
            payload = dec_obj.payload().get_claim_value<std::string>("hostId"); //payload hostID
            if (payload.find('|') != string::npos){
                v = split(payload , '|');
                for (int i = 0 ; i < v.size() ; i ++) {
                    if (!v[i].compare(hostId)) {
                        return true;
                    }
                }
            }
            else{
                if (!payload.compare(hostId)) {
                    return true;
                }
            }
        }
        catch(const exception& e){
            return false;
        }
    }
    return false;
}

bool checkLicense::init()
{
    auto pub_key = read_from_file(pub_key_path);
    auto token = read_from_file(token_path); //license file
	try {
        dec_obj = jwt::decode(token, algorithms({"RS256"}), verify(true), secret(pub_key));
    }
    catch (...) {
        return false;
    }
    try{
        hostId = exec("hostid"); //OS hostID
    }
    catch(...){
        return false;
    }
    return true;
}

void checkLicense::clear()
{
    for(auto i : v) {
        i.clear();
    }
    v.clear();
}