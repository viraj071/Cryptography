#include <fstream>
#include <sstream>
#include <iostream>
#include "cryptopp/hmac.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "hashmac.h"
#include "hexa.h"

using namespace CryptoPP;

// Method to generate key for HMAC
std::string HashMac::generate_key(){
	std::string encoded;
	AutoSeededRandomPool prng;

	byte key[16];
	prng.GenerateBlock(key, 16);

	encoded.clear();
	StringSource ss1(key, 16, true,
	    new HexEncoder(
	        new StringSink(encoded)
	    ) // HexEncoder
	); // StringSource

	return encoded;
}

// Method to generate HMAC using SHA256
void HashMac::generate_hmac(std::string keyfile,std::string filename,std::string savefilename){
	std::string encoded = generate_key();
	std::ofstream ofs(keyfile.c_str(),std::ios_base::app);
	ofs << encoded;
	ofs.close();
	Hexa h;
	byte *key = h.hex_to_byte_decoder(encoded);
	std::ifstream in(filename.c_str());
	std::stringstream ss;
	ss << in.rdbuf();
	std::string plaintext=ss.str();
	ss.str("");
	in.close();
	std::string mac;
	try
	{
	    HMAC< SHA256 > hmac(key, 16);

	    StringSource ss2(plaintext, true,
	        new HashFilter(hmac,
	            new StringSink(mac)
	        ) // HashFilter
	    ); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
	    std::cerr << e.what() << std::endl;
	    exit(1);
	}

	encoded.clear();
	StringSource ss3(mac, true,
	    new HexEncoder(
	        new StringSink(encoded)
	    ) // HexEncoder
	); // StringSource
	std::ofstream out(savefilename.c_str());
	out << encoded;
	out.close();
}
