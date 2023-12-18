#include "otacverify.h"

int OtacVerify::getIP(char* box, int box_len)
{
    struct ifaddrs *addresses;
    if (getifaddrs(&addresses) == -1){
            //printf("getifaddrs call failed\n");
            return 0;
    }
    struct ifaddrs *address = addresses;
    while (address)
    {
        int family = address->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6)
        {
            if (strcmp(address->ifa_name , "lo"))
            {
                const int family_size = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                getnameinfo(address->ifa_addr,
                            family_size,
                            box,
                            box_len,
                            0,
                            0,
                            NI_NUMERICHOST);
                break;
            }
        }
        address = address->ifa_next;
    }
    freeifaddrs(addresses);
    return 1;
}

OtacVerify::OtacVerify(const char * _otac)
{
    ver_json["otac"] = _otac;
    ver_json["pcDeviceId"] = "127.0.0.1";
    ver_json["systemId"] = "1";
    ver_json["apiKey"] = "PLC_567052367261557962726962304c69424b374546433867766b4a314a33715851";

}
OtacVerify::OtacVerify()
{
    //cout << "input parameter(otac)"<< endl;
    return;
}

void OtacVerify::Otac_Set_Host_IP()
{
    char* ip = new char[IP_SIZE];
    if (!getIP(ip, IP_SIZE)){
        //cout << "Get host ip fail" << endl;
        delete[] ip;
        return;
    }
    ver_json["plcDeviceId"] = ip;
    delete[] ip;
}

void OtacVerify::Otac_Set_Post(const char* url)
{
    if(!curl_handle.init()) {
        return;
    }
    curl_handle.set_header_content("Content-Type","application/json");
    JsonStr = writer.write(ver_json);
    curl_handle.set_post(JsonStr);
    curl_handle.set_server_info(url);
}

void OtacVerify::Otac_Request()
{
    if (curl_handle.request()){
        return ;
    }
    response = curl_handle.response();
    Json::Reader reader;
    reader.parse(response, root);
}


Json::Value OtacVerify::Otac_Get_Root(){ return root ; }

std::string OtacVerify::Otac_get_response(){ return response ; }

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