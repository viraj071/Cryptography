#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string>
#include "cryptopp/osrng.h"
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "bcipher.h"
#include "hexa.h"
#include "hashmac.h"

using namespace CryptoPP;

std::string str_xor(std::string const & s1, std::string const & s2);

void BCipher::encrypt(std::string keyfile,std::string filename,std::string savefilename){
	AutoSeededRandomPool rnd;

	// Generate a random key
	byte key[AES::DEFAULT_KEYLENGTH];
	memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
	rnd.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);

	// Generate a random IV
	byte iv[AES::BLOCKSIZE];
	memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
	rnd.GenerateBlock(iv, AES::BLOCKSIZE);

	Hexa b;
	std::string plaintext = b.hex_to_string_decoder(filename);
	unsigned char *ciphertext= new unsigned char[plaintext.size()+1];
	ciphertext[plaintext.size()]='\0';

	// Convert the key to hex and save it to key.txt file
	std::ofstream outkey(keyfile.c_str());
	outkey << b.byte_to_hex_encoder(key,AES::DEFAULT_KEYLENGTH);

	// Convert the iv to hex and save it to key.txt file
	outkey << b.byte_to_hex_encoder(iv,AES::BLOCKSIZE);
	outkey.close();

	// Run AES encryption in CFB Mode
	CFB_Mode<AES>::Encryption cfbEncryption(key, AES::DEFAULT_KEYLENGTH, iv);
	cfbEncryption.ProcessData(ciphertext,(unsigned char*)(plaintext.c_str()),plaintext.size()+1);

	// Save the encrypted contents to file
	std::ofstream out(savefilename.c_str());
	out << b.byte_to_hex_encoder(ciphertext,plaintext.size());
	out.close();

	std::cout<<"Performing HMAC using SHA256 on file..."<<savefilename<<std::endl;
	HashMac h;
	h.generate_hmac(keyfile,savefilename,"hmac_"+savefilename);
}

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
void BCipher::xorfunc_pre(std::string keyfile,std::string filename,std::string savefilename){
	std::ifstream in(filename.c_str());
	std::stringstream ss;
	ss<< in.rdbuf();
	std::string input = ss.str();
	in.close();

	Hexa h;
	std::string temp = h.gen_random_hex(input.size());

	std::ofstream ofs(keyfile.c_str(),std::ios_base::app);
	ofs << temp;
	ofs.close();

	std::string xorval = str_xor(input,temp);
	std::ofstream out(savefilename.c_str());
	out << xorval;
	out.close();
}
