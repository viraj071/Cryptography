#include <string>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <bitset>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <iomanip>
#include "hexa.h"


// Method to convert Byte to Hex
std::string Hexa::byte_to_hex_encoder(unsigned char *array, int len){
	std::stringstream ss;
	for(int i=0;i<len;++i)
		ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)array[i];
	return ss.str();
}

// Method to convert Hex to Byte
unsigned char* Hexa::hex_to_byte_decoder(std::string input){
	size_t len = input.length();
	unsigned char *inval = new unsigned char[input.length()/2];
	int j=0;
	for(size_t i=0;i<len;i+=2){
		std::stringstream ss;
		unsigned int buffer;
		ss << input.substr(i,2);
		ss >> std::hex >> buffer;
		inval[j]=static_cast<unsigned char>(buffer);
		j++;
		ss.str(std::string());
		ss.clear();
	}
	return inval;
}

// Method to convert String to Hex
void Hexa::string_to_hex_encoder(std::string filename){

	std::ifstream in(filename.c_str());
	std::stringstream ss;
	ss << in.rdbuf();
	std::string input=ss.str();
	size_t len = input.length();
	static const char* const lut = "0123456789ABCDEF";

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	std::ofstream out(filename.c_str());
	out << output;
	in.close();
	out.close();
}

// Method to convert Hex to String
std::string Hexa::hex_to_string_decoder(std::string filename){
	std::ifstream in(filename.c_str());
	std::stringstream ss;
	ss << in.rdbuf();
	std::string input=ss.str();
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();
	if (len & 1) throw std::invalid_argument("odd length");

	std::string output;
	output.reserve(len / 2);
	for (size_t i = 0; i < len; i += 2)
	{
		char a = std::toupper(input[i]);
		const char* p = std::lower_bound(lut, lut + 16, a);
		if (*p != a) throw std::invalid_argument("not a hex digit");

		char b = std::toupper(input[i + 1]);
		const char* q = std::lower_bound(lut, lut + 16, b);
		if (*q != b) throw std::invalid_argument("not a hex digit");

		output.push_back(((p - lut) << 4) | (q - lut));
	}
	in.close();
	return output;
}
