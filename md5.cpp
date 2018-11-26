#define _CRYPTO_UTIL_H_
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <iostream>
#include <string>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/default.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
using namespace CryptoPP;

int main()
{
  std::string digest, inData;
  std::cout << "please input a string" << std::endl;
  std::cin >> inData;
  Weak1::MD5 md5;
  StringSource(inData, true, new HashFilter(md5, new HexEncoder(new StringSink(digest))));

  std::cout<< digest <<std::endl;
}
