#ifndef __HASHMAC_H_INCLUDED_
#define __HASHMAC_H_INCLUDED_

class HashMac{
public:
	bool verify_hmac(std::string k,std::string plaintext,std::string mac);
};

#endif
