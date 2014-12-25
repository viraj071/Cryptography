#include <fstream>
#include <iostream>
#include <sstream>
#include "bcipher.h"

int main(int argc, char* argv[]){
	if(argc != 3){
		std::cout<<"Invalid number of arguments"<<std::endl;
		return -1;
	}
	std::string keyfile,filename;
	std::string input = argv[1];
	std::stringstream ss(input);

	ss >> keyfile;
	ss.str("");
	input = argv[2];
	std::stringstream ss1(input);
	ss1 >> filename;

	BCipher a;

	//Authorize phase
	std::cout<<"Authorize Phase"<<std::endl;
	a.xorfunc_auth(keyfile,filename,"sfilename.txt");
	a.fkgenerator(keyfile,filename);
	std::cout<<"Authorize Phase complete"<<std::endl;

	return 0;
}
