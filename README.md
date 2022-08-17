octo-encryption-cpp
==============

[![Encryption Linux Build Pipeline](https://github.com/ofiriluz/octo-encryption-cpp/actions/workflows/linux.yml/badge.svg)](https://github.com/ofiriluz/octo-encryption-cpp/actions/workflows/linux.yml)
[![Encryption Windows Build Pipeline](https://github.com/ofiriluz/octo-encryption-cpp/actions/workflows/windows.yml/badge.svg)](https://github.com/ofiriluz/octo-encryption-cpp/actions/workflows/windows.yml)
[![Encryption Mac Build Pipeline](https://github.com/ofiriluz/octo-encryption-cpp/actions/workflows/mac.yml/badge.svg)](https://github.com/ofiriluz/octo-encryption-cpp/actions/workflows/mac.yml)

Encryption library in CPP, with base interfaces implemented with openssl

Interfaces implemented:
- Base64
- Secure random
- Digests
- Encryptors and secure strings


Usage
=====

Using the encryption library is based on openssl mostly, as such different interfaces can be used as follows:

Base64
------

```cpp
std::string text = "This is some text";
auto encoded = octo::encryption::Base64::base64_encode(text);
auto decoded = octo::encryption::Base64::base64_decode(encoded);
```

Secure random
-------------

Generate a secure random of size X, returns a vector of random bytes
```cpp
auto secure_random = octo::encryption::SecureRandom::generate_random(10);
```

Digests
-------

Supported Digests implemented:
- Sha224
- Sha256
- Sha384
- Sha512

Generating hashes for different digests
```cpp
auto digest = std::make_shared<octo::encryption::ssl::Sha512Digest>();
digest->update("SomeText");
digest->update("SomeOtherText");
auto hash = digest->finalize();
```

Encryptors and secure strings
-----------------------------

A base encryptor can encrypt and decrypt strings with materials (salts for the encryption)

Above that, we can define Secure / Encrypted strings, which are self destructed encrypted strings

We have 2 layers of secure strings:
- Layer 0 - SecureString, cleanup memory no encryption
- Layer 1 - SingleLayerEncryptedString, Single layer encryption

Above that, more can be implemented based on the interfaces defined

Example encryptor usage:
```cpp
auto material = std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"Key1", "Key2", "Key3"});
auto e = octo::encryption::ssl::SSLEncryptor(std::make_shared<octo::encryption::ssl::SSLCipher>("AES256"));
auto encrypted = e.encrypt("Text", material);
std::string output;
auto decrypted = e.decrypt(encrypted, material, output)
```

Example SingleEncryptedString usage:
```cpp
auto encryptor = std::make_shared<octo::encryption::ssl::SSLEncryptor>(
    std::make_shared<octo::encryption::ssl::SSLCipher>("AES256"));
auto material = std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"Key1", "Key2", "Key3"});
octo::encryption::SingleEncryptedString encrypted_string(encryptor);
// Encryption
encrypted_string.set(input_plain_string, material);

// Decryption
auto output_plain_string = encrypted_string.get();
```

