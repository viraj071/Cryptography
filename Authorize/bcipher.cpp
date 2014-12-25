#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string>
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "bcipher.h"

using namespace CryptoPP;

const int HMAC_KEYLENGTH = 16;

// Utility method to perform Hex XOR
static inline unsigned int value(char c)
{
    if (c >= '0' && c <= '9') { return c - '0';      }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

// Method to perform Hex XOR
std::string str_xor(std::string const & s1, std::string const & s2)
{

    static char const alphabet[] = "0123456789ABCDEF";

    std::string result;
    result.reserve(s1.length());

    for (std::size_t i = 0; i != s1.length(); ++i)
    {
        unsigned int v = value(s1[i]) ^ value(s2[i]);

        result.push_back(alphabet[v]);
    }

    return result;
}

// Perform XOR and store to file
void BCipher::xorfunc_auth(std::string keyfile,std::string filename,std::string savefilename){
	std::ifstream in(filename.c_str());
	std::stringstream ss;
	ss<< in.rdbuf();
	std::string input = ss.str();
	ss.str("");
	in.close();

	std::ifstream in1(keyfile.c_str());
	ss << in1.rdbuf();
	std::string temp = ss.str();
	ss.str("");
	in1.close();

	temp = temp.substr(HMAC_KEYLENGTH*2+AES::DEFAULT_KEYLENGTH*2+AES::BLOCKSIZE*2,temp.size()-(AES::DEFAULT_KEYLENGTH*2+AES::BLOCKSIZE*2+HMAC_KEYLENGTH*2));
	std::string xorval = str_xor(input,temp);
	std::ofstream out(savefilename.c_str());
	out << xorval;
	out.close();
}

void BCipher::fkgenerator(std::string keyfile,std::string filename){
	std::ifstream inkey(keyfile.c_str());
	std::stringstream ss;
	ss << inkey.rdbuf();
	std::string key=ss.str();
	std::string keyfilename = key.substr(HMAC_KEYLENGTH*2+AES::BLOCKSIZE*2+AES::DEFAULT_KEYLENGTH*2,key.size()-(AES::DEFAULT_KEYLENGTH*2+AES::BLOCKSIZE*2+HMAC_KEYLENGTH*2));
	std::string hmackey = key.substr(AES::DEFAULT_KEYLENGTH*2+AES::BLOCKSIZE*2,HMAC_KEYLENGTH*2);
	key = key.substr(0,AES::DEFAULT_KEYLENGTH*2+AES::BLOCKSIZE*2);
	ss.str("");
	inkey.close();

	std::ifstream in(filename.c_str());
	ss << in.rdbuf();
	std::string contents = ss.str();
	in.close();

	if(key.size()>contents.size()){
		contents+=std::string(key.size()-contents.size(),'A');
	}
	else{
		contents=contents.substr(0,key.size());
	}
	std::string fk = str_xor(key,contents);
	fk = hmackey + keyfilename + fk;
	std::ofstream outfk("fkey.txt");
	outfk << fk;
	outfk.close();
}
