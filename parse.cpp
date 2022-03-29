#include <iostream>
#include <regex>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>


using namespace std;

enum Protocol { RSN, OPEN };

const std::string WHITESPACE = " \n\r\t\f\v";

const vector<string> tokens = {"freq","SSID","signal","RSN"};

void jsonize(vector<string>& lines, vector<string>& json);
void filer(vector<string> lines, vector<string>& grep);

std::string ltrim(const std::string &s)
{
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == std::string::npos) ? "" : s.substr(start);
}
 
std::string rtrim(const std::string &s)
{
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}
 
std::string trim(const std::string &s) {
    return rtrim(ltrim(s));
}

bool isValidMACAddress(string str)
{

        // Regex to check valid MAC address
        const regex pattern(
        "^([0-9A-Fa-f]{2}[:-]){5}"
        "([0-9A-Fa-f]{2})|([0-9a-"
        "fA-F]{4}\\.[0-9a-fA-F]"
        "{4}\\.[0-9a-fA-F]{4})$");

        if (str.empty())
        {
                return false;
        }

        if (regex_match(str, pattern))
        {
                return true;
        }
        else
        {
                return false;
        }
}

bool has_MAC(string line, string& mac){

        int pos=0;
        string str;
        int len = strlen(line.c_str());
        while(true){
                str = line.substr(pos,17);  //cout << endl << str << endl;
                if (strlen(str.c_str()) < 17) return false;
                if (isValidMACAddress(str)){ mac=str; return true; }
                else pos++;
        }

        return false;
}

bool filter(string filename, vector<string>& linesvec){
	
	string MAC; 

        std::ifstream in(filename.c_str());
        if(!in)
        {
                std::cerr << "Cannot open the File : "<<filename<<std::endl;
                return false;
        }
        std::string (line);
        while (std::getline(in, line))
        {
                if(line.size() > 0)
		if(
			       	( has_MAC(line, MAC) == true ) ||	
				( line.find("freq:") != std::string::npos ) ||
				( line.find("signal:") != std::string::npos ) ||
				( line.find("SSID:") != std::string::npos ) ||
				( line.find("RSN:") != std::string::npos ) ||
				( line.find("Version:") != std::string::npos ) ||
				( line.find("Group cipher:") != std::string::npos ) ||
				( line.find("Pairwise ciphers:") != std::string::npos ) ||
				( line.find("Authentication suites:") != std::string::npos ) ||
				( line.find("* Capabilities:") != std::string::npos ) 
		  ) linesvec.push_back(line); 
        }

        in.close();

        return true;
}

void jsonize(vector<string>& linesvec){

	string MAC;
	linesvec.insert(linesvec.begin(), "[");

	for(auto& line:linesvec){
               if( has_MAC((line), MAC) == true ){
                 line = string("{") + string("\"BSS\":" ) + string("\"") + string(MAC) + string("\"") + string(",");
	       }
               if( (line).find("freq:") != std::string::npos ){
                 string freq= string(trim((line).substr(line.find(":")+1))) ;
                 line = string("\"freq\"") + string(":") + string("\"") + freq + string("\",");
	       }
               if( (line).find("signal:") != std::string::npos ){
                 string freq= string(trim((line).substr((line).find(":")+1))) ;
                 line = string("\"signal\"") + string(":") + string("\"") + freq + string("\",");
	       }
               if( (line).find("SSID:") != std::string::npos ){
                 string freq= string(trim((line).substr((line).find(":")+1))) ;
                 line = string("\"SSID\"") + string(":") + string("\"") + freq + string("\",");
	       }
               if( (line).find("RSN:") != std::string::npos ){
		       line = string("\"RSN\":") + string("{");
	       }
               if( ((line).find("Version:") != std::string::npos ) &&
			       ((line).find("RSN:") != std::string::npos ) ){
                      string version= string(trim((line).substr((line).find(":")+1))) ;
                      line = string("\"Version\"") + string(":") + string("\"") + version + string("\",");
               }
               if( (line).find("* Group cipher:") != std::string::npos ){
                      string gc= string(trim((line).substr((line).find(":")+1))) ;
                      line = string("\"Group cipher\"") + string(":") + string("\"") + gc + string("\",");
	       } 

               if( (line).find("* Pairwise ciphers:") != std::string::npos ){
                      string pc= string(trim((line).substr((line).find(":")+1))) ;
                      line = string("\"Pairwise ciphers\"") + string(":") + string("\"") + pc + string("\",");
	       } 
               if( (line).find("* Authentication suites:") != std::string::npos ){
                      string as= string(trim((line).substr((line).find(":")+1))) ;
                      line = string("\"Authentication suites\"") + string(":") + string("\"") + as + string("\",");
	       } 
               if( (line).find("* Capabilities:") != std::string::npos ){
                      string caps= string(trim((line).substr((line).find(":")+1))) ;
                      line = string("\"Capabilities\"") + string(":") + string("\"") + caps + string("}") + string("},");
		}
	}
	linesvec.push_back("]");

}


int main(){
	vector<string> linesvec;
	filter("orig.txt", linesvec);
	jsonize(linesvec);

	vector<string>::iterator start, end;

	bool if_erased=1;
	while(true){
		//cout << "while loop" << endl;
		for(auto itr=linesvec.begin(); itr < linesvec.end();){
		if_erased=0;
			if((*itr).find(")}},") != std::string::npos ) {
				start=itr;itr++;
				for(auto itr2=itr; itr2 < linesvec.end();){
					if((*itr2).find("\"BSS\"") != std::string::npos ) {
						// cout <<"start: " << (*start) << endl;
						// cout <<"end: " << (*itr2) << endl;
						linesvec.erase(itr,itr2);
						if_erased=1;
					}
				itr2++;
				}
			}
		itr++;
		}
	if (if_erased==0) break;
	}

	for(auto line:linesvec){
		cout << line << endl;
	}

}


































