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
#include "cryptopp/rsa.h"
#include "cryptopp/pssr.h"
#include "bcipher.h"
#include "hexa.h"
#include "hashmac.h"

using namespace CryptoPP;

const int HMAC_KEYLENGTH = 16;

std::string str_xor(std::string const & s1, std::string const & s2);

void BCipher::decrypt(std::string fkfile, std::string efn, std::string encryptedfile,std::string decryptedfile){
	std::cout<<"Generating RSA keys..."<<std::endl;

	// Generate keys
	AutoSeededRandomPool rng;

	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 3072);

	RSA::PrivateKey privateKey(params);
	RSA::PublicKey publicKey(params);
	std::cout<<"Sending public key to user..."<<std::endl;
	std::string plain, cipher, recovered;
	std::stringstream ss;
	std::ifstream infk(fkfile.c_str());
	ss << infk.rdbuf();
	std::string fk = ss.str();
	ss.str("");
	infk.close();
	plain=fk;

	////////////////////////////////////////////////
	// Encryption
	std::cout<<"User encrypting fk and HMAC of uploaded file with public key..."<<std::endl;
	RSAES_OAEP_SHA_Encryptor e(publicKey);

	StringSource ss1(plain, true,
	    new PK_EncryptorFilter(rng, e,
	        new StringSink(cipher)
	   ) // PK_EncryptorFilter
	); // StringSource

	std::cout<<"Encryption Complete.\nUser now sharing the encrypted fk and HMAC of uploaded file over unsecure channel..."<<std::endl;
	////////////////////////////////////////////////
	std::cout<<"Peer receives the encrypted files."<<std::endl;
	std::cout<<"Decrypting the files using his private key..."<<std::endl;

	// Decryption
	RSAES_OAEP_SHA_Decryptor d(privateKey);

	StringSource ss2(cipher, true,
	    new PK_DecryptorFilter(rng, d,
	        new StringSink(recovered)
	   ) // PK_DecryptorFilter
	); // StringSource
	fk=recovered;
	Hexa b;
	std::string hmackey = fk.substr(0,HMAC_KEYLENGTH*2);
	std::ifstream inefn(efn.c_str());
	ss << inefn.rdbuf();
	std::string efncontents = ss.str();

	std::string keyfilename = fk.substr(HMAC_KEYLENGTH*2,efncontents.size());
	fk=fk.substr(HMAC_KEYLENGTH*2+efncontents.size(),fk.size()-(efncontents.size()+HMAC_KEYLENGTH*2));

	std::string fn1 = str_xor(efncontents,keyfilename);
	ss.str("");
	inefn.close();

	if(fn1.size() < fk.size()){
		fn1+=std::string(fk.size()-fn1.size(),'A');
	}
	else{
		fn1=fn1.substr(0,fk.size());
	}
	std::string keyiv = str_xor(fk,fn1);
	std::string skey = keyiv.substr(0,AES::DEFAULT_KEYLENGTH*2);
	std::string siv = keyiv.substr(AES::DEFAULT_KEYLENGTH*2,AES::BLOCKSIZE*2);

	// Get key in byte form from hex
	byte *key=b.hex_to_byte_decoder(skey);

	// Get iv in byte form from hex
	byte *iv=b.hex_to_byte_decoder(siv);

	// Get cipher text from file
	std::ifstream in(encryptedfile.c_str());
	ss << in.rdbuf();
	std::string input=ss.str();
	size_t len = input.length();
	int ctlen = len/2;
	ss.str("");
	in.close();

	std::ifstream inmd5(("hmac_"+encryptedfile).c_str());
	ss << inmd5.rdbuf();
	std::string hmaccontents = ss.str();
	ss.str("");
	inmd5.close();

	std::cout<<"Checking HMAC of downloaded file ..."<<std::endl;
	HashMac h;
	if(h.verify_hmac(hmackey,input,hmaccontents)){
		std::cout<<"File authenticated and integrity maintained!"<<std::endl;
	}
	else{
		std::cout<<"File could not be authenticated!"<<std::endl;
	}

	// Convert ciphertext to bytes from hex
	byte *ciphertext=b.hex_to_byte_decoder(input);

	unsigned char *plaintext = new unsigned char[ctlen+1];
	plaintext[ctlen]='\0';

	// Decrypt the file and store contents to file
	CFB_Mode<AES>::Decryption cfbDecryption(key, AES::DEFAULT_KEYLENGTH, iv);
	cfbDecryption.ProcessData(plaintext, ciphertext, ctlen+1);
	std::string x = b.byte_to_hex_encoder(plaintext,ctlen);
	std::ofstream outfinal(decryptedfile.c_str());
	outfinal << x;
	outfinal.close();
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

