#include <gtest/gtest.h>
#include <fstream>

#include "../Include/DigitalSignature.hpp"

inline bool FileExist(const std::string& name) {
    std::ifstream fileIn(name.c_str());
    return fileIn.good();
}

TEST(DocExample, DocExampleTest) {
    // How to create a pair of RSA signature files
    std::string publicPemFileName{"rsa-public.pem"};
    std::string privatePemFileName{"rsa-private.pem"};
    DigitalSignature::CreateKeyPairFile(publicPemFileName, privatePemFileName);

    // How to encode a message
    DigitalSignature::Encode encodeSignature(privatePemFileName);
    std::string message{"This is a message test."};
    std::string signature = encodeSignature.RSASign(message);
    std::cout << "Signature: [" << signature << "]" << std::endl;

    // How to verify a message with a signature
    DigitalSignature::Decode decodeSignature(publicPemFileName);
    bool result = decodeSignature.VerifySignature(message, signature);
    if (result) {
        std::cout << "The message is valid." << std::endl;
    } else {
        std::cout << "The message is invalid." << std::endl;
    }
}

TEST(DigitalSignature, KeyFileWasCreatedTest) {
    // Arrange
    std::string publicPemFileName{"rsa-public.pem"};
    std::string privatePemFileName{"rsa-private.pem"};
    // Act
    DigitalSignature::CreateKeyPairFile(publicPemFileName, privatePemFileName);
    // Assert
    EXPECT_TRUE(FileExist(publicPemFileName));
    EXPECT_TRUE(FileExist(privatePemFileName));
}

TEST(DigitalSignature, ValidSignatureTest) {
    // Arrage
    std::string publicPemFileName{"rsa-public.pem"};
    std::string privatePemFileName{"rsa-private.pem"};
    DigitalSignature::CreateKeyPairFile(publicPemFileName, privatePemFileName);
    DigitalSignature::Encode encodeSign(privatePemFileName);
    DigitalSignature::Decode decodeSign(publicPemFileName);
    // Act
    std::string message{"This is a message test."};
    std::string signature = encodeSign.RSASign(message);
    // Assert
    EXPECT_TRUE(decodeSign.VerifySignature(message, signature));
}

TEST(DigitalSignature, InvalidSignatureTest) {
    // Arrage
    std::string publicPemFileName{"rsa-public.pem"};
    std::string privatePemFileName{"rsa-private.pem"};
    DigitalSignature::CreateKeyPairFile(publicPemFileName, privatePemFileName);
    DigitalSignature::Encode encodeSign(privatePemFileName);
    DigitalSignature::Decode decodeSign(publicPemFileName);
    // Act
    std::string message{"This is a message test."};
    std::string signature = encodeSign.RSASign(message);
    message.append("change the message");
    // Assert
    EXPECT_FALSE(decodeSign.VerifySignature(message, signature));
}

TEST(DigitalSignature, Validate10SignatureTest) {
    // Arrage
    std::string publicPemFileName{"rsa-public.pem"};
    std::string privatePemFileName{"rsa-private.pem"};
    DigitalSignature::CreateKeyPairFile(publicPemFileName, privatePemFileName);
    DigitalSignature::Encode encodeSign(privatePemFileName);
    DigitalSignature::Decode decodeSign(publicPemFileName);
    // Act
    for (int i = 0; i < 10; i++) {
        std::string message = "This is the message test number: " + std::to_string(i);
        std::string signature = encodeSign.RSASign(message);
        // Assert
        EXPECT_TRUE(decodeSign.VerifySignature(message, signature));
    }
}
