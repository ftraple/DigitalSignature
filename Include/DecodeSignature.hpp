#ifndef DECODE_SIGNATURE_H
#define DECODE_SIGNATURE_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

class DecodeSignature {

    public:

    DecodeSignature(const std::string& publicKey);

    bool VerifySignature(const std::string& message, const std::string& signature);

    private:

    RSA* m_rsa;
    std::shared_ptr<EVP_MD_CTX> m_mdContext;
    std::shared_ptr<EVP_PKEY> m_publicKey;
};

#endif // DECODE_SIGNATURE_H