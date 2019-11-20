#include <gtest/gtest.h>
#include <fstream>

#include "../Include/EncodeSignature.hpp"
#include "../Include/DecodeSignature.hpp"

inline bool FileExist(const std::string& name) {
    std::ifstream fileIn(name.c_str());
    return fileIn.good();
}

TEST(Test, Demo) {

    std::string publicPemFileName{"rsa-public.pem"};
    std::string privatePemFileName{"rsa-private.pem"};

    EncodeSignature encodeSign;
    encodeSign.CreateKeyPairFile(publicPemFileName, privatePemFileName);

    EXPECT_TRUE(FileExist(publicPemFileName));
    EXPECT_TRUE(FileExist(privatePemFileName));
}