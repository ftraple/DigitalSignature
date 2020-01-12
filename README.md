# Digital Signature

This library is used to assign memory block data using RSA private/public keys.

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
To compile the library with the tests and run it you can do:

```bash
git clone git@github.com:ftraple/DigitalSignature.git
cd DigitalSignature
mkdir build
cd build 
cmake -DBUILD_TESTS=ON ..
make test
sudo make install
```

## How To Encode


```c++
function main() {
  std::cout << "This is a message." << std::endl;
  return EXIT_SUCCESS;
}
```

## How To Decode
