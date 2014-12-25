#ifndef __HEXA_H_INCLUDED_
#define __HEXA_H_INCLUDED_


class Hexa{
public:
	std::string hex_to_string_decoder(std::string filename);
	void string_to_hex_encoder(std::string filename);
	std::string byte_to_hex_encoder(unsigned char *array, int len);
	unsigned char* hex_to_byte_decoder(std::string input);
};

#endif
