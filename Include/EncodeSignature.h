#ifndef ENCODE_SIGNATURE_H
#define ENCODE_SIGNATURE_H

#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

class EncodeSignature {

    public:

    EncodeSignature();

    EncodeSignature(const std::string& privateKeyFileName);

    void CreateKeyPairFile(
        const std::string& publicKeyFileName,
        const std::string& privateKeyFileName);

    void SetPrivateKey(const std::string& privateKeyFileName);

    const std::string RSASign(const std::string& message);

    private:

    RSA* m_rsa;
    std::shared_ptr<EVP_MD_CTX> m_mdContext;
    std::shared_ptr<EVP_PKEY> m_privateKey;
};

#endif // ENCODE_SIGNATURE_H