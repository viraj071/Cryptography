#ifndef __HASHMAC_H_INCLUDED_
#define __HASHMAC_H_INCLUDED_

class HashMac{
public:
	std::string generate_key();
	void generate_hmac(std::string keyfile,std::string filename,std::string savefilename);
};

#endif
