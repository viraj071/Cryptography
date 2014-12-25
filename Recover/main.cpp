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
	std::string fkeyfile,file,filename;
	std::string input = argv[1];
	std::stringstream ss(input);
	ss >> file;
	ss.str("");

	input = argv[2];
	std::stringstream ss1(input);
	ss1 >> filename;
	ss.str("");

	input = argv[3];
	std::stringstream ss2(input);
	ss2 >> fkeyfile;

	//Recover phase
	BCipher a;
	std::cout<<"Recover Phase"<<std::endl;
	a.decrypt(fkeyfile,filename,file,"sfile.txt");
	std::cout<<"Recover Phase complete"<<std::endl;

	return 0;
}
