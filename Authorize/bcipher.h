#ifndef __BCIPHER_H_INCLUDED_
#define __BCIPHER_H_INCLUDED_

class BCipher{
public:
	void xorfunc_auth(std::string keyfile,std::string filename,std::string savefilename);
	void fkgenerator(std::string keyfile,std::string file);
};
#endif
