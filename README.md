# Digital Signature

This library is used to assign messages using RSA public and private keys.

## How To Install

To install this library you need to download the project and compile it with Cmake.

```bash
git clone git@github.com:ftraple/DigitalSignature.git
cd DigitalSignature
mkdir build
cd build 
cmake ..
make
sudo make install
```
To compile the library with the tests and run it, you need to set a cmake option.

```bash
cmake -DBUILD_TESTS=ON ..
make test
```

This library is checked for memory leaks whit [valgrind](https://valgrind.org/) tool.

### How To Use

This is a complete example to show how to use this library.

```c++
#include <iostream>
#include "DigitalSignature.hpp"

int main() {

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

    return EXIT_SUCCESS;
}
```
