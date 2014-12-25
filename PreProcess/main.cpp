#include <fstream>
#include <iostream>
#include <sstream>
#include "bcipher.h"
#include "hexa.h"

int main(int argc, char* argv[]){
	if(argc != 4){
		std::cout<<"Invalid number of arguments"<<std::endl;
		return -1;
	}
	std::string keyfile,file,filename;
	std::string input = argv[1];
	std::stringstream ss(input);
	ss >> keyfile;
	ss.str("");

	input = argv[2];
	std::stringstream ss1(input);
	ss1 >> file;
	ss.str("");

	input = argv[3];
	std::stringstream ss2(input);
	ss2 >> filename;

	Hexa h;
	std::cout<<"Setting Up Environment" <<std::endl;
	h.string_to_hex_encoder(file);
	h.string_to_hex_encoder(filename);
	std::cout<<"Environment Set"<<std::endl;

	BCipher a;
	// PreProcess phase
	std::cout<<"Preprocess Phase"<<std::endl;
	a.encrypt(keyfile,file,"efile.txt");
	a.xorfunc_pre(keyfile,filename,"efilename.txt");
	std::cout<<"Preprocess Phase complete"<<std::endl;

	return 0;
}
