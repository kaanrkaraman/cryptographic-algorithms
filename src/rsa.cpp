#include "rsa.h"
#include <cstdlib>
#include <ctime>
#include <stdexcept>

RSA::RSA() {
	srand(static_cast<unsigned>(time(nullptr)));
}

RSA::~RSA() = default;

void RSA::generate_key_pair(int bitLength) {
	p = generate_prime(bitLength / 2);
	do {
		q = generate_prime(bitLength / 2);
	} while (p == q);

	n = p * q;
	phi = (p - 1) * (q - 1);

	do {
		e = rand() % (phi - 2) + 2;
	} while (gcd(e, phi) != 1);

	d = mod_inverse();
}

std::vector<long long> RSA::encrypt(const std::string &message) const {
	std::vector<long long> cipher_text;
	for (char ch : message) {
		auto m = static_cast<long long>(static_cast<unsigned char>(ch));
		long long c = mod_exp(m, e, n);
		cipher_text.push_back(c);
	}
	return cipher_text;
}

std::pair<std::string, std::string> RSA::get_public_key() const {
	return {
		std::to_string(n),
		std::to_string(e)
	};
}

std::string RSA::get_private_key() const {
	return std::to_string(d);
}

bool RSA::is_prime(long long num) {
	if (num <= 1) return false;
	if (num <= 3) return true;
	if (num % 2 == 0 || num % 3 == 0) return false;
	for (int i = 5; i * i <= num; i += 6) {
		if (num % i == 0 || num % (i + 2) == 0) return false;
	}
	return true;
}

long long RSA::generate_prime(int bitLength) {
	long long min = 1 << (bitLength - 1);
	long long max = (1 << bitLength) - 1;

	long long candidate;
	do {
		candidate = rand() % (max - min + 1) + min;
	} while(!is_prime(candidate));
	return candidate;
}

long long RSA::gcd(long long a, long long b) {
	while (b != 0) {
		long long temp = b;
		b = a % b;
		a = temp;
	}
	return a;
}

long long RSA::mod_exp(long long base, long long exp, long long mod) {
	long long result = 1;
	base = base % mod;

	while (exp > 0) {
		if (exp % 2 == 1) {
			result = (result * base) % mod;
		}
		exp = exp >> 1;
		base = (base * base) % mod;
	}
	return result;
}

long long RSA::mod_inverse() const {
	long long t = 0, newT = 1;
	long long r = phi, newR = e;

	while (newR != 0) {
		long long quotient = r / newR;

		long long tempT = t;
		t = newT;
		newT = tempT - quotient * newT;

		long long tempR = r;
		r = newR;
		newR = tempR - quotient * newR;
	}

	if (r > 1) {
		throw std::runtime_error("e is not invertible.");
	}
	if (t < 0) {
		t += phi;
	}
	return t;
}

std::string RSA::decrypt(const std::vector<long long> &ciphertext) const {
	std::string plaintext;

	for (long long ch : ciphertext) {
		long long m = mod_exp(ch, d, n);

		plaintext += static_cast<char>(m);
	}

	return plaintext;
}