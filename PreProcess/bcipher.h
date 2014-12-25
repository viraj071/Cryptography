#ifndef __BCIPHER_H_INCLUDED_
#define __BCIPHER_H_INCLUDED_

class BCipher{
public:
	void encrypt(std::string keyfile,std::string file,std::string savefile);
	void xorfunc_pre(std::string keyfile,std::string filename,std::string savefilename);
};
#endif
