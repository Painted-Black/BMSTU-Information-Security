#include "rsa.h"
#include "debug.h"
#include "utils.h"
#include <assert.h>

string RSA::crypt(const string &str)
{
	if (mKeysGenerated == false)
	{
		generateKeys(16);
	}
	string binCipherText;
	for (uint64_t i = 0, n = str.size(); i < n; ++i)
	{
		uint8_t cur_byte = str.at(i);
		uint64_t cipher_byte = moduloDegree(cur_byte, mPublicKey.first, mPublicKey.second);
		string bin_cipher_byte = _uintToBin(cipher_byte);
		bin_cipher_byte = supplement(bin_cipher_byte, 32);
		binCipherText += bin_cipher_byte;
	}
	string res = _binStrToSymbols(binCipherText, 8);
	return res;
}

string RSA::encrypt(const string &str)
{
	string res;
	string bin_str;
	for (uint8_t c: str)
	{
		string tmp = _uintToBin(c);
		tmp = supplement(tmp, 8);
		bin_str += tmp;
	}
	int64_t count = bin_str.size() / 32;
	for (int i = 0; i < count; ++i)
	{
		string cur_substr = bin_str.substr(i * 32, 32);
		int64_t cur_cipher = _binStrToUlong(cur_substr);
		uint8_t init_substr = moduloDegree(cur_cipher, mSecretKey.first, mSecretKey.second);
		res += init_substr;
	}
	return res;
}

void RSA::generateKeys(uint16_t min)
{
	uint64_t P = PrimeNumberGenerator::generate(min, UINT16_MAX);
	uint64_t Q = PrimeNumberGenerator::generate(min, UINT16_MAX);
	mN = P * Q; // длина алфавита
	uint32_t fi = (P - 1) * (Q - 1);
	int32_t E = findE(fi);
	int32_t D = findD(fi, E, mN);
	mPublicKey.first = E;
	mPublicKey.second = mN;
	mSecretKey.first = D;
	mSecretKey.second = mN;

	Debug::debug("P: %", P);
	Debug::debug("Q: %", Q);
	Debug::debug("fi: %", fi);
	Debug::debug("E: %", E);
	Debug::debug("N: %", mN);

	Debug::info("public key = <%, %>", E, mN);
	Debug::info("secret key = <%, %>", D, mN);
	mKeysGenerated = true;
}

int64_t RSA::findD(int64_t fi, int64_t E, int64_t N)
{
	vector<int64_t> ext_gcf = extendedEuclideanAlgorithm(fi, E);
	Debug::debug("NOD: %, alpha: %, beta %", ext_gcf[0], ext_gcf[1], ext_gcf[2]);
	int64_t D = ext_gcf[2];
	if (D < 0)
	{
		D = N + D;
	}
	return D;
}

int64_t RSA::findE(int64_t fi)
{
	int64_t gcf = 0;
	int64_t E;
	for ( ; gcf != 1; )
	{
		E = 2 + random() % (fi - 2);
		gcf = EuclideanAlgorithm(E, fi);
		Debug::debug("E: %, fi: %, gcf: %", E, fi, gcf);
	}
	return E;
}

/**
 * @brief Нахождение НОД
 * @param a
 * @param b
 * @return
 */
int64_t RSA::EuclideanAlgorithm(int64_t a, int64_t b)
{
	assert(a != 0 && b != 0);
	if (a == b)
	{
		return a;
	}
	int64_t r;
	while (b != 0)
	{
		r = a % b;
		a = b;
		b = r;
	}
	return a;
}

/**
 * @brief Нахождение НОД и коэффициентов x, y таких, что a * x + b * y = НОД(a, b).
 * @param a
 * @param b
 * @return [НОД, x, y]
 */
vector<int64_t> RSA::extendedEuclideanAlgorithm(int64_t a, int64_t b)
{
	assert(a > 0 && b > 0);
	int64_t old_r = a, r = b;
	int64_t old_s = 1, s = 0;
	int64_t old_t = 0, t = 1;

	while (r != 0)
	{
		int64_t quotient = old_r / r;
		int64_t prov = r;
		r = old_r - quotient * prov;
		old_r = prov;

		prov = s;
		s = old_s - quotient * prov;
		old_s = prov;

		prov = t;
		t = old_t - quotient * prov;
		old_t = prov;
	}
	int64_t _min = min(old_s, old_t);
	int64_t _max = max(old_s, old_t);
	vector<int64_t> res;
	if (a > b)
	{
		res = {old_r, _min, _max};
	}
	else
	{
		res = {old_r, _max, _min};
	}
	return res;
}

uint64_t RSA::moduloDegree(uint64_t base, uint64_t degree, uint64_t mod)
{
	uint64_t r = 1;
	while (degree > 0)
	{
		if (degree % 2 == 1) // если нечетное
		{
			r = (r * base) % mod;
		}
		base = (base * base) % mod;
		degree >>= 1; // degree = degree / 2
	}
	return r;
}
