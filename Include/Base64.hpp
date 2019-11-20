#ifndef BASE64_H
#define BASE64_H

#include <iostream>
#include <vector>
#include <memory>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>

const std::string Base64Encode(const std::vector<unsigned char>& binaryMessage);

const std::vector<unsigned char> Base64Decode(const std::string& base64Message);

#endif // BASE64_H