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

namespace DigitalSignature {

    using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
    using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
    using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

    void CreateKeyPairFile(
        const std::string& publicKeyFileName,
        const std::string& privateKeyFileName);

    class Encode {

        public:

            Encode(const std::string& privateKeyFileName);

            const std::string RSASign(const std::string& message);

        private:

            RSA* m_rsa;
            std::shared_ptr<EVP_MD_CTX> m_mdContext;
            std::shared_ptr<EVP_PKEY> m_privateKey;
    };

    class Decode {

        public:

        Decode(const std::string& publicKey);

        bool VerifySignature(const std::string& message, const std::string& signature);

        private:

        RSA* m_rsa;
        std::shared_ptr<EVP_MD_CTX> m_mdContext;
        std::shared_ptr<EVP_PKEY> m_publicKey;
    };
}

#endif // ENCODE_SIGNATURE_H