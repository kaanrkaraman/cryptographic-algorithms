#ifndef CRYPTOGRAPHICALGORTIHMS_RSA_H
#define CRYPTOGRAPHICALGORTIHMS_RSA_H

#include <utility>
#include <vector>
#include <string>

class RSA {
private:
	/**
	 * Public exponent e should be a small, odd prime number, typically 3 or 17 or 65537, mostly the latter
	 * Private exponent d is the modular multiplicative inverse of e modulo ɸ(n), so that (e * d) ≡ 1 (mod ɸ(n))
	 * Public key pair is (n, e) whereas private key pair is (n, d)
	 *
	 * To encrypt a message we will calculate C = M^e mod n, where M is the message and C is the cipher text
	 * M = C^d mod n will use private key to decrypt the message
	 */

	long long p{}, q{};     // Large prime numbers
	long long n{};          // n = p * q, n is the modulus for the public and private keys
	long long phi{};        // phi = (p - 1) * (q - 1), phi is the Euler's totient function of n
	long long e{}, d{};     // e and d are the public and private exponents respectively

	static bool is_prime(long long num);
	static long long generate_prime(int bitLength);
	static long long gcd(long long a, long long b);
	long long mod_inverse() const;
	static long long mod_exp(long long base, long long exp, long long mod);

public:
	RSA();
	~RSA();

	void generate_key_pair(int bitLength);

	std::vector<long long> encrypt(const std::string &message) const;
	std::string decrypt(const std::vector<long long> &cipher_text) const;

	std::pair<std::string, std::string> get_public_key() const;
	std::string get_private_key() const;
};

#endif //CRYPTOGRAPHICALGORTIHMS_RSA_H
