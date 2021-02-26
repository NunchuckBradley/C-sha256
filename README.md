# C++ SHA256 encoder

A sha256 hasher using C++


```

#include "m_sha256.h"

int main() {
    // input
    std::string string = "hello world";
    
    // convert input into binary value, unsigned char   
    unsigned char out[string.length()];
    for (int i = 0; i < string.length(); i++) {
        out[i] = string.at(i);
    }
    
    // run the algorithm with paramters (unsigned char pointer, size in bytes)
    uint256<256> digest = M_sha256::sha256AlgorithmUint256Input((unsigned char*)out, sizeof(out));
    
    // use uint256<256> .getHex() to get the value in hex string form
    // .getHex(false) will print in little endian, big endian is default
    std::cout << "expected: " << "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" << std::endl;
    std::cout << "digest  : " << digest.getHex(false) << std::endl;
}

```
