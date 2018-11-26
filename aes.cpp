#ifndef _CRYPTO_UTIL_H_
#define _CRYPTO_UTIL_H_

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <iostream>
#include <sstream>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/default.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

enum AESKeyLength
{
    AES_KEY_LENGTH_16 = 16, AES_KEY_LENGTH_24 = 24, AES_KEY_LENGTH_32 = 32  //密钥的长度
};

class CCryptoUtil
{
public:
    static int encrypt4aes(const std::string &inData, const std::string &strKey,
            std::string &outData, std::string &errMsg)
    {
        outData = "";
        errMsg = "";

        if (inData.empty() || strKey.empty()) // 判断待加密的字符串或者密钥是否为空
        {
            errMsg = "indata or key is empty!!";
            return -1;
        }

        unsigned int iKeyLen = strKey.length();

        if (iKeyLen != AES_KEY_LENGTH_16 && iKeyLen != AES_KEY_LENGTH_24  //判断密钥的长度是否符合要求
                && iKeyLen != AES_KEY_LENGTH_32)
        {
            errMsg = "aes key invalid!!";
            return -2;
        }

        byte iv[AES::BLOCKSIZE];
        int iResult = 0;

        try
        {
            CBC_Mode<AES>::Encryption e;
            e.SetKeyWithIV((byte*) strKey.c_str(), iKeyLen, iv);
            StringSource ss(inData, true, new StreamTransformationFilter(e, new StringSink(outData)));

        } catch (const CryptoPP::Exception& e)
        {
            errMsg = "Encryptor throw exception!!";
            iResult = -3;
        }

        return iResult;
    }

    static int decrypt4aes(const std::string &inData, const std::string &strKey,
            std::string &outData, std::string &errMsg)
    {
        outData = "";
        errMsg = "";

        if (inData.empty() || strKey.empty())
        {
            errMsg = "indata or key is empty!!";
            return -1;
        }

        unsigned int iKeyLen = strKey.length();

        if (iKeyLen != AES_KEY_LENGTH_16 && iKeyLen != AES_KEY_LENGTH_24
                && iKeyLen != AES_KEY_LENGTH_32)
        {
            errMsg = "aes key invalid!!";
            return -2;
        }

        byte iv[AES::BLOCKSIZE];
        int iResult = 0;

        try
        {
            CBC_Mode<AES>::Decryption d;
            d.SetKeyWithIV((byte*) strKey.c_str(), iKeyLen, iv);
            StringSource ss(inData, true,
                    new StreamTransformationFilter(d, new StringSink(outData)));
        }
        catch (const CryptoPP::Exception& e)
        {
            errMsg = "Encryptor throw exception";
            iResult = -3;
        }

        return iResult;
    }

};

int main(int argc, char **argv)
{
    std::string strCipher;     //待加密的字符串
    std::string strKey;       //用来加解密的密钥

    std::cout << "Please enter a string" << std::endl;
    std::cin >> strCipher;
    std::cout << "please enter a key, you just can write 16,24 or 32 words as a key" << std::endl;
    std::cin >> strKey;

    std::string strResult;
    std::string strErrMsg;
    int iResult = CCryptoUtil::encrypt4aes(strCipher, strKey, strResult, strErrMsg);
    if(iResult)
    {
        std::cout << "CCryptoUtil::encrypt4aes failed,errMsg:" << strErrMsg;
        return -1;
    }

    std::string strPlainText;
    iResult = CCryptoUtil::decrypt4aes(strResult,strKey,strPlainText,strErrMsg);
    if(iResult)
    {
        std::cout << "CCryptoUtil::decrypt4aes failed,errMsg:" << strErrMsg;
        return -2;
    }

    std::cout << "PlainText:"<<strPlainText << std::endl;
}

#endif//_CRYPTO_UTIL_H_
