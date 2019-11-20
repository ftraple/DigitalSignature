#include <gtest/gtest.h>
#include <fstream>

#include "../Include/EncodeSignature.hpp"
#include "../Include/DecodeSignature.hpp"

inline bool FileExist(const std::string& name) {
    std::ifstream fileIn(name.c_str());
    return fileIn.good();
}

TEST(DigitalSignature, TestIfKeyFileWasCreated) {
    // Arrange
    std::string publicPemFileName{"rsa-public.pem"};
    std::string privatePemFileName{"rsa-private.pem"};
    EncodeSignature encodeSign;
    // Act
    encodeSign.CreateKeyPairFile(publicPemFileName, privatePemFileName);
    // Assert
    ASSERT_TRUE(FileExist(publicPemFileName));
    ASSERT_TRUE(FileExist(privatePemFileName));
}

TEST(DigitalSignature, TestValidSignature) {
    // Arrage
    EncodeSignature encodeSign("rsa-private.pem");
    DecodeSignature decodeSign("rsa-public.pem");
    // Act
    std::string message{"This is a message test."};
    std::string signature = encodeSign.RSASign(message);
    // Assert
    ASSERT_TRUE(decodeSign.VerifySignature(message, signature));
}

TEST(DigitalSignature, TestInvalidSignature) {
    // Arrage
    EncodeSignature encodeSign("rsa-private.pem");
    DecodeSignature decodeSign("rsa-public.pem");
    // Act
    std::string message{"This is a message test."};
    std::string signature = encodeSign.RSASign(message);
    message.append("change the message");
    // Assert
    ASSERT_FALSE(decodeSign.VerifySignature(message, signature));
}

TEST(DigitalSignature, Test_10_ValidSignature) {
    // Arrage
    EncodeSignature encodeSign("rsa-private.pem");
    DecodeSignature decodeSign("rsa-public.pem");
    // Act
    for (int i = 0; i < 10; i++) {
        std::string message = "This is the message test number: " + std::to_string(i);
        std::string signature = encodeSign.RSASign(message);
        // Assert
        ASSERT_TRUE(decodeSign.VerifySignature(message, signature));
    }
}
