#include "EncodeSignature.hpp"
#include "Base64.hpp"

RSA* OpenPrivateKey(const std::string& privateKeyFileName) {
    std::unique_ptr<FILE, decltype(&::fclose)> privateKeyFile(fopen(privateKeyFileName.c_str(),"rb"), &fclose);
    if(!privateKeyFile) {
        return nullptr;
    }
    RSA* rsa = nullptr;
    rsa = PEM_read_RSAPrivateKey(privateKeyFile.get(), &rsa, nullptr, nullptr);
    fclose(privateKeyFile.get());
    return rsa;
}

EncodeSignature::EncodeSignature() {
    m_rsa = nullptr;
    m_mdContext = std::shared_ptr<EVP_MD_CTX>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    m_privateKey = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free);
}

EncodeSignature::EncodeSignature(const std::string& privateKeyFileName) {
    m_rsa = OpenPrivateKey(privateKeyFileName);
    m_mdContext = std::shared_ptr<EVP_MD_CTX>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    m_privateKey = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free);
    EVP_PKEY_assign_RSA(m_privateKey.get(), m_rsa);
}

void EncodeSignature::CreateKeyPairFile(
    const std::string& publicKeyFileName,
    const std::string& privateKeyFileName)
{
    // Generate a new key
    BN_ptr bn(BN_new(), ::BN_free);
    if (BN_set_word(bn.get(), RSA_F4) < 1) {
        return;
    }
    RSA_ptr rsa(RSA_new(), ::RSA_free);
    if (RSA_generate_key_ex(rsa.get(), 2048, bn.get(), NULL) < 1) {
        return;
    }
    // Save the public key
    BIO_FILE_ptr pemPublic(BIO_new_file(publicKeyFileName.c_str(), "w"), ::BIO_free);
    if (PEM_write_bio_RSAPublicKey(pemPublic.get(), rsa.get()) < 1 ) {
        return;
    }
    // Save the private key
    BIO_FILE_ptr pemPrivate(BIO_new_file(privateKeyFileName.c_str(), "w"), ::BIO_free);
    if (PEM_write_bio_RSAPrivateKey(pemPrivate.get(), rsa.get(), nullptr, nullptr, 0, nullptr, nullptr) < 1) {
        return;
    }
}

void EncodeSignature::SetPrivateKey(const std::string& privateKeyFileName) {
    m_rsa = OpenPrivateKey(privateKeyFileName);
    EVP_PKEY_assign_RSA(m_privateKey.get(), m_rsa);
}

const std::string EncodeSignature::RSASign(const std::string& message) {

    if (m_rsa == nullptr) {
        return std::string("");
    }
    if (EVP_DigestSignInit(m_mdContext.get(), nullptr, EVP_sha256(), nullptr, m_privateKey.get())< 1) {
        return std::string("");
    }

    if (EVP_DigestSignUpdate(m_mdContext.get(), message.c_str(), message.size()) < 1) {
        return std::string("");
    }

    size_t signatureSize;
    if (EVP_DigestSignFinal(m_mdContext.get(), nullptr, &signatureSize) < 1) {
        return std::string("");
    }

    std::vector<unsigned char> signature(signatureSize);
    if (EVP_DigestSignFinal(m_mdContext.get(), signature.data(), &signatureSize) < 1) {
        return std::string("");
    }
    EVP_MD_CTX_reset(m_mdContext.get());

   return Base64Encode(signature);
}
