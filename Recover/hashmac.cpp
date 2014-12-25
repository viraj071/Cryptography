#include <fstream>
#include <sstream>
#include <iostream>
#include "cryptopp/hmac.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "hashmac.h"
#include "hexa.h"

using namespace CryptoPP;

// Method to verify HMAC
bool HashMac::verify_hmac(std::string k,std::string plaintext,std::string mac){
	Hexa h;
	byte *key = h.hex_to_byte_decoder(k);
	std::string encoded = mac;
	std::string decoded;

	HexDecoder decoder;

	decoder.Attach( new StringSink( decoded ) );
	decoder.Put( (byte*)encoded.data(), encoded.size() );
	decoder.MessageEnd();
	mac = decoded;

	try
	{
	    HMAC< SHA256 > hmac(key, 16);
	    const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

	    StringSource(plaintext + mac, true,
	        new HashVerificationFilter(hmac, NULL, flags)
	    ); // StringSource

	    return true;
	}
	catch(const CryptoPP::Exception& e)
	{
	    std::cerr << e.what() << std::endl;
	    return false;
	}
}
