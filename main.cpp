#include <iostream>
#include "rsa.h"

int main() {
	RSA rsa;

	rsa.generate_key_pair(16);

	auto publicKey = rsa.get_public_key();
	std::string privateKey = rsa.get_private_key();
	std::cout << "Public Key: n = " << publicKey.first << ", e = " << publicKey.second << std::endl;
	std::cout << "Private Key: d = " << privateKey << std::endl;

	std::string message;
	std::cout << "Enter a message to encrypt: ";
	std::getline(std::cin, message);
	std::cout << "Original Message: " << message << std::endl;

	auto ciphertext = rsa.encrypt(message);

	std::cout << "Encrypted Message: ";
	for (long long c : ciphertext) {
		std::cout << c << " ";
	}
	std::cout << std::endl;

	std::string decryptedMessage = rsa.decrypt(ciphertext);
	std::cout << "Decrypted Message: " << decryptedMessage << std::endl;

	return 0;
}