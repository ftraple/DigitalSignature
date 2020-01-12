#include "DigitalSignature.hpp"
#include "Base64.hpp"

RSA* OpenPublicKey(const std::string& publicFileName) {
    std::unique_ptr<FILE, decltype(&::fclose)> publicKeyFile(fopen(publicFileName.c_str(),"rb"), &fclose);
    if(!publicKeyFile) {
        return nullptr;
    }
    RSA* rsa = nullptr;
    rsa = PEM_read_RSAPublicKey(publicKeyFile.get(), &rsa, nullptr, nullptr);
    return rsa;    
}

DigitalSignature::Decode::Decode(const std::string& publicKey) {
    m_rsa = OpenPublicKey(publicKey);
    m_mdContext = std::shared_ptr<EVP_MD_CTX>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    m_publicKey = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free);
    EVP_PKEY_assign_RSA(m_publicKey.get(), m_rsa);
}

bool DigitalSignature::Decode::VerifySignature(const std::string& message, const std::string& signature) {

    if (m_rsa == nullptr) {
        return false;
    }

    std::vector<unsigned char> binaryMessage = Base64Decode(signature);

    if (EVP_DigestVerifyInit(m_mdContext.get(), nullptr, EVP_sha256(), nullptr, m_publicKey.get()) < 1) {
        return false;
    }
    if (EVP_DigestVerifyUpdate(m_mdContext.get(), message.c_str(), message.size()) < 1) {
        return false;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_mdContext.get(), binaryMessage.data(), binaryMessage.size());
    EVP_MD_CTX_reset(m_mdContext.get());
    if (AuthStatus < 1) {
        return false;
    }
    return true;
}

