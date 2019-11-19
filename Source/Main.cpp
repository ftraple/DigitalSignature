#include <iostream>

#include "EncodeSignature.h"
#include "DecodeSignature.h"


int main() {

    EncodeSignature encodeSignature;

    const std::string publicKeyFileName{"Bin/rsa_public.pem"};
    const std::string privateKeyFileName{"Bin/rsa_private.pem"};

    encodeSignature.CreateKeyPairFile(publicKeyFileName, privateKeyFileName);
    encodeSignature.SetPrivateKey(privateKeyFileName);

    // Create a message
    std::string message("This message will receive a digital signature.");
    // Sign the message
    std::string signature = encodeSignature.RSASign(message);
    std::cout << "signature = " << signature << std::endl;

    // Load the public RSA key
    DecodeSignature decodeSignature(publicKeyFileName);
    
    // Verify if the signature is true
    if (decodeSignature.VerifySignature(message, signature)) {
        std::cout << "This is a valid signature!" << std::endl;
    }
    else {
        std::cout << "This is NOT a valid signature!" << std::endl;
    }

    // Invalidate the message adding a dot.
    message.append(".");
    // Verify if the signature is true
    if (decodeSignature.VerifySignature(message, signature)) {
        std::cout << "This is a valid signature!" << std::endl;
    }
    else {
        std::cout << "This is NOT a valid signature!" << std::endl;
    }

    // Verify if the signature is true
    std::string message2("This message will receive a digital signature.");
    if (decodeSignature.VerifySignature(message2, signature)) {
        std::cout << "This is a valid signature!" << std::endl;
    }
    else {
        std::cout << "This is NOT a valid signature!" << std::endl;
    }

    return EXIT_SUCCESS;
}
