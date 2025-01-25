#include "pch.h"
#include <codecvt>
#include <shellapi.h>
#include <ShlObj_core.h>
#include <TlHelp32.h>

#include "CodeTool.h"
#include "PCInfoTool.h"

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static string _base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char _base64_pad = '=';

inline MD5::uint4 MD5::F(uint4 x, uint4 y, uint4 z) {
	return x&y | ~x&z;
}

inline MD5::uint4 MD5::G(uint4 x, uint4 y, uint4 z) {
	return x&z | y&~z;
}

inline MD5::uint4 MD5::H(uint4 x, uint4 y, uint4 z) {
	return x^y^z;
}

inline MD5::uint4 MD5::I(uint4 x, uint4 y, uint4 z) {
	return y ^ (x | ~z);
}

inline MD5::uint4 MD5::rotate_left(uint4 x, int n) {
	return (x << n) | (x >> (32 - n));
}

inline void MD5::FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
	a = rotate_left(a + F(b, c, d) + x + ac, s) + b;
}

inline void MD5::GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
	a = rotate_left(a + G(b, c, d) + x + ac, s) + b;
}

inline void MD5::HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
	a = rotate_left(a + H(b, c, d) + x + ac, s) + b;
}

inline void MD5::II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
	a = rotate_left(a + I(b, c, d) + x + ac, s) + b;
}

MD5::MD5()
{
	init();
}

MD5::MD5(const string &text)
{
	init();
	update(text.c_str(), text.length());
	finalize();
}

void MD5::init()
{
	finalized = false;

	count[0] = 0;
	count[1] = 0;

	// load magic initialization constants.  
	state[0] = 0x67452301;
	state[1] = 0xefcdab89;
	state[2] = 0x98badcfe;
	state[3] = 0x10325476;
}

void MD5::decode(uint4 output[], const uint1 input[], size_type len)
{
	for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((uint4)input[j]) | (((uint4)input[j + 1]) << 8) |
		(((uint4)input[j + 2]) << 16) | (((uint4)input[j + 3]) << 24);
}

void MD5::encode(uint1 output[], const uint4 input[], size_type len)
{
	for (size_type i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = input[i] & 0xff;
		output[j + 1] = (input[i] >> 8) & 0xff;
		output[j + 2] = (input[i] >> 16) & 0xff;
		output[j + 3] = (input[i] >> 24) & 0xff;
	}
}

void MD5::transform(const uint1 block[blocksize])
{
	uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
	decode(x, block, blocksize);

	/* Round 1 */
	FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
	FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
	HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
	II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	// Zeroize sensitive information.  
	memset(x, 0, sizeof x);
}

void MD5::update(const unsigned char input[], size_type length)
{
	// compute number of bytes mod 64  
	size_type index = count[0] / 8 % blocksize;

	// Update number of bits  
	if ((count[0] += (length << 3)) < (length << 3))
		count[1]++;
	count[1] += (length >> 29);

	// number of bytes we need to fill in buffer  
	size_type firstpart = 64 - index;

	size_type i;

	// transform as many times as possible.  
	if (length >= firstpart)
	{
		// fill buffer first, transform  
		memcpy(&buffer[index], input, firstpart);
		transform(buffer);

		// transform chunks of blocksize (64 bytes)  
		for (i = firstpart; i + blocksize <= length; i += blocksize)
			transform(&input[i]);

		index = 0;
	}
	else
		i = 0;

	// buffer remaining input  
	memcpy(&buffer[index], &input[i], length - i);
}

void MD5::update(const char input[], size_type length)
{
	update((const unsigned char*)input, length);
}

MD5& MD5::finalize()
{
	static unsigned char padding[64] = {
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	if (!finalized) {
		// Save number of bits  
		unsigned char bits[8];
		encode(bits, count, 8);

		// pad out to 56 mod 64.  
		size_type index = count[0] / 8 % 64;
		size_type padLen = (index < 56) ? (56 - index) : (120 - index);
		update(padding, padLen);

		// Append length (before padding)  
		update(bits, 8);

		// Store state in digest  
		encode(digest, state, 16);

		// Zeroize sensitive information.  
		memset(buffer, 0, sizeof buffer);
		memset(count, 0, sizeof count);

		finalized = true;
	}

	return *this;
}

string MD5::hexdigest() const
{
	if (!finalized)
		return "";

	char buf[33];
	for (int i = 0; i < 16; i++)
		sprintf(buf + i * 2, "%02x", digest[i]);
	buf[32] = 0;

	return string(buf);
}

ostream& operator<<(ostream& out, MD5 md5)
{
	return out << md5.hexdigest();
}

string CodeTool::EncodeBase64(const unsigned char * str, int bytes)
{
	int num = 0;
	string _encode_result;
	const unsigned char * current;
	current = str;
	while (bytes > 2) {
		_encode_result += _base64_table[current[0] >> 2];
		_encode_result += _base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
		_encode_result += _base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
		_encode_result += _base64_table[current[2] & 0x3f];

		current += 3;
		bytes -= 3;
	}
	if (bytes > 0)
	{
		_encode_result += _base64_table[current[0] >> 2];
		if (bytes % 3 == 1) {
			_encode_result += _base64_table[(current[0] & 0x03) << 4];
			_encode_result += "==";
		}
		else if (bytes % 3 == 2) {
			_encode_result += _base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
			_encode_result += _base64_table[(current[1] & 0x0f) << 2];
			_encode_result += "=";
		}
	}
	return _encode_result;
}

string CodeTool::DecodeBase64(const char *str, int bytes)
{
	//解码表
	const char DecodeTable[] =
	{
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
		-2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
		-2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
	};
	int bin = 0, i = 0, pos = 0;
	string _decode_result;
	const char *current = str;
	char ch;
	while ((ch = *current++) != '\0' && bytes-- > 0)
	{
		if (ch == _base64_pad) { // 当前一个字符是“=”号
			/*
			先说明一个概念：在解码时，4个字符为一组进行一轮字符匹配。
			两个条件：
			1、如果某一轮匹配的第二个是“=”且第三个字符不是“=”，说明这个带解析字符串不合法，直接返回空
			2、如果当前“=”不是第二个字符，且后面的字符只包含空白符，则说明这个这个条件合法，可以继续。
			*/
			if (*current != '=' && (i % 4) == 1) {
				return NULL;
			}
			continue;
		}
		ch = DecodeTable[ch];
		//这个很重要，用来过滤所有不合法的字符
		if (ch < 0) { /* a space or some other separator character, we simply skip over */
			continue;
		}
		switch (i % 4)
		{
		case 0:
			bin = ch << 2;
			break;
		case 1:
			bin |= ch >> 4;
			_decode_result += bin;
			bin = (ch & 0x0f) << 4;
			break;
		case 2:
			bin |= ch >> 2;
			_decode_result += bin;
			bin = (ch & 0x03) << 6;
			break;
		case 3:
			bin |= ch;
			_decode_result += bin;
			break;
		}
		i++;
	}
	return _decode_result;
}

void CodeTool::DecodeBase64(const char *str, int bytes, char*& dest, int& len)
{
	//解码表
	const char DecodeTable[] =
	{
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
		-2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
		-2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
		-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
	};
	int bin = 0, i = 0, pos = 0;
	std::string _decode_result;
	const char *current = str;
	char ch;
	while ((ch = *current++) != '\0' && bytes-- > 0)
	{
		if (ch == _base64_pad) { // 当前一个字符是“=”号
			/*
			先说明一个概念：在解码时，4个字符为一组进行一轮字符匹配。
			两个条件：
			1、如果某一轮匹配的第二个是“=”且第三个字符不是“=”，说明这个带解析字符串不合法，直接返回空
			2、如果当前“=”不是第二个字符，且后面的字符只包含空白符，则说明这个这个条件合法，可以继续。
			*/
			if (*current != '=' && (i % 4) == 1) {
				return;
			}
			continue;
		}
		ch = DecodeTable[ch];
		//这个很重要，用来过滤所有不合法的字符
		if (ch < 0) { /* a space or some other separator character, we simply skip over */
			continue;
		}
		switch (i % 4)
		{
		case 0:
			bin = ch << 2;
			break;
		case 1:
			bin |= ch >> 4;
			_decode_result += bin;
			bin = (ch & 0x0f) << 4;
			break;
		case 2:
			bin |= ch >> 2;
			_decode_result += bin;
			bin = (ch & 0x03) << 6;
			break;
		case 3:
			bin |= ch;
			_decode_result += bin;
			break;
		}
		i++;
	}
	len = _decode_result.length();
	dest = new char[_decode_result.length()];
	for (size_t i = 0; i < _decode_result.length(); i++)
		dest[i] = _decode_result[i];
}

string CodeTool::GbkToUtf8(const char *src_str)
{
	int len = MultiByteToWideChar(CP_ACP, 0, src_str, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[len + 1];
	memset(wstr, 0, len + 1);
	MultiByteToWideChar(CP_ACP, 0, src_str, -1, wstr, len);
	len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
	char* str = new char[len + 1];
	memset(str, 0, len + 1);
	WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
	string strTemp = str;
	if (wstr) delete[] wstr;
	if (str) delete[] str;
	return strTemp;
}

string CodeTool::Utf8ToGbk(const char* src_str)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, src_str, -1, NULL, 0);
	wchar_t* wszGBK = new wchar_t[len + 1];
	memset(wszGBK, 0, len * 2 + 2);
	MultiByteToWideChar(CP_UTF8, 0, src_str, -1, wszGBK, len);
	len = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, NULL, 0, NULL, NULL);
	char* szGBK = new char[len + 1];
	memset(szGBK, 0, len + 1);
	WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, szGBK, len, NULL, NULL);
	string strTemp(szGBK);
	if (wszGBK) delete[] wszGBK;
	if (szGBK) delete[] szGBK;
	return strTemp;
}

std::wstring CodeTool::Str2WStr(const string& str)
{
	try
	{
		USES_CONVERSION;
		return A2W(str.c_str());
	}
	catch (const std::exception&)
	{
		return L"";
	}
}

std::string CodeTool::WStr2Str(const wstring& wstr)
{
	try
	{
		USES_CONVERSION;
		return W2A(wstr.c_str());
	}
	catch (const std::exception&)
	{
		return "";
	}
}

const string CodeTool::UnicodeToUtf8(const std::wstring & wstr)
{
	std::string ret;
	try {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> wcv;
		ret = wcv.to_bytes(wstr);
	}
	catch (const std::exception & e) {
		std::cerr << e.what() << std::endl;
	}
	return ret;
}

const wstring CodeTool::Utf8ToUnicode(const std::string & str)
{
	std::wstring ret;
	try {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> wcv;
		ret = wcv.from_bytes(str);
	}
	catch (const std::exception & e) {
		std::cerr << e.what() << std::endl;
	}
	return ret;
}

const string CodeTool::GetDesktopPath()
{
	char cDesktop[MAX_PATH] = { 0 };
	LPITEMIDLIST lp = NULL;
	SHGetSpecialFolderLocation(0, CSIDL_DESKTOPDIRECTORY, &lp);
	if (lp != NULL)
	{
		SHGetPathFromIDListA(lp, cDesktop);
		CoTaskMemFree(lp);
	}
	return cDesktop;
}

const string CodeTool::GetAppDataPath()
{
	char cDesktop[MAX_PATH] = { 0 };
	LPITEMIDLIST lp = NULL;
	SHGetSpecialFolderLocation(0, CSIDL_APPDATA, &lp);
	if (lp != NULL)
	{
		SHGetPathFromIDListA(lp, cDesktop);
		CoTaskMemFree(lp);
	}
	return cDesktop;
}

const bool CodeTool::CreateLinkFile(LPCTSTR szStartAppPath, LPCTSTR szAddCmdLine, LPCOLESTR szDestLnkPath, LPCTSTR szIconPath)
{
	HRESULT hr = CoInitialize(NULL);
	if (SUCCEEDED(hr))
	{
		IShellLink *pShellLink;
		hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&pShellLink);
		if (SUCCEEDED(hr))
		{
			pShellLink->SetPath(szStartAppPath);
			std::wstring strTmp = szStartAppPath;
			int nStart = strTmp.find_last_of(L"/\\");
			pShellLink->SetWorkingDirectory(strTmp.substr(0, nStart).c_str());
			pShellLink->SetArguments(szAddCmdLine);
			if (szIconPath)
			{
				pShellLink->SetIconLocation(szIconPath, 0);
			}
			IPersistFile* pPersistFile;
			hr = pShellLink->QueryInterface(IID_IPersistFile, (void**)&pPersistFile);
			if (SUCCEEDED(hr))
			{
				hr = pPersistFile->Save(szDestLnkPath, FALSE);
				if (SUCCEEDED(hr))
				{
					return true;
				}
				pPersistFile->Release();
			}
			pShellLink->Release();
		}
		CoUninitialize();
	}
	return false;
}

string CodeTool::md5(const std::string str)
{
	MD5 md5 = MD5(str);
	return md5.hexdigest();
}

const bool CodeTool::IsFileDir(LPCTSTR lpFilePath)
{
	DWORD dwAttr = GetFileAttributes(lpFilePath);
	return ((dwAttr != INVALID_FILE_ATTRIBUTES) && (dwAttr & FILE_ATTRIBUTE_DIRECTORY));
}

void CodeTool::DeleteDir(LPCTSTR lpDirPath, wstring& wstrContent)
{
	wstring sDir = lpDirPath;
	wstring sFind = sDir + _T("\\*.*");
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(sFind.c_str(), &fd);
	if (INVALID_HANDLE_VALUE != hFind)
	{
		do
		{
			wstring sFile = sDir + _T("\\") + fd.cFileName;
			if (_tcsicmp(fd.cFileName, _T(".")) == 0 || _tcsicmp(fd.cFileName, _T("..")) == 0)
				continue;
			else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				DeleteDir(sFile.c_str(), wstrContent);
				continue;
			}
			if (!DeleteFile(sFile.c_str()))
				wstrContent.append(fd.cFileName).append(L"|");;
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}
	RemoveDirectory(lpDirPath);
}

string& CodeTool::Replace_all(string& src, const string& old_value, const string& new_value) {
	// 每次重新定位起始位置，防止上轮替换后的字符串形成新的old_value
	for (string::size_type pos(0); pos != string::npos; pos += new_value.length()) {
		if ((pos = src.find(old_value, pos)) != string::npos) {
			src.replace(pos, old_value.length(), new_value);
		}
		else break;
	}
	return src;
}

const string convertTimeStamp2TimeStr(const time_t& timeStamp) {
	try
	{
		struct tm* timeinfo = nullptr;
		char buffer[80] = { 0, };
		timeinfo = localtime(&timeStamp);
		strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
		return string(buffer);
	}
	catch (const std::exception&)
	{
		return "";
	}
}

const bool CodeTool::QueryAHPluGinHellzyInfo()
{
	return true;
	//try
	//{
	//	AHPluGinInfo::clearHellzy();
	//	const string strQueryUrl = "https://ppcl.dxinzf.com/webapi/game/diabloActivityInfo";
	//	CWininetHttp http;
	//	const string res = http.RequestJsonInfo2(strQueryUrl.c_str());
	//	const auto bHttp = (http.GetHttpState() == Hir_Success);
	//	if (bHttp)
	//	{
	//		do
	//		{
	//			const auto cRoot = cJSON_Parse(res.c_str());
	//			if (!cRoot)
	//				break;
	//			const auto pCode = cJSON_GetObjectItem(cRoot, "code");
	//			if (!pCode || (pCode->type != cJSON_String))
	//				break;
	//			const std::string iCode = pCode->valuestring;
	//			if (strcmp("0", iCode.c_str())) {
	//				AHPluGinInfo::g_bQueryStuHell = true;
	//				break;
	//			}
	//			const auto pData = cJSON_GetObjectItem(cRoot, "data");
	//			if (!pData || (pData->type != cJSON_Object))
	//				break;
	//			const auto pName = cJSON_GetObjectItem(pData, "name");
	//			if (pName && pName->type == cJSON_String)
	//				AHPluGinInfo::g_sName = pName->valuestring;
	//			const auto pActivityFinishTime = cJSON_GetObjectItem(pData, "activityFinishTime");
	//			if (pActivityFinishTime && pActivityFinishTime->type == cJSON_String)
	//				AHPluGinInfo::g_lActivityFinishTime = pActivityFinishTime->valuestring;
	//			const auto pActivityDuration = cJSON_GetObjectItem(pData, "activityDuration");
	//			if (pActivityDuration && pActivityDuration->type == cJSON_Number)
	//				AHPluGinInfo::g_lActivityDuration = pActivityDuration->valuedouble;
	//			const auto pIntervalTime = cJSON_GetObjectItem(pData, "intervalTime");
	//			if (pIntervalTime && pIntervalTime->type == cJSON_String)
	//				AHPluGinInfo::g_lIntervalTime = pIntervalTime->valuestring;
	//			const auto pIntervalDuration = cJSON_GetObjectItem(pData, "intervalDuration");
	//			if (pIntervalDuration && pIntervalDuration->type == cJSON_Number)
	//				AHPluGinInfo::g_lIntervalDuration = pIntervalDuration->valuedouble;
	//		} while (false);
	//		if (AHPluGinInfo::g_lIntervalDuration == 0)
	//			AHPluGinInfo::g_bQueryStuHell = true;
	//	}
	//	else
	//		AHPluGinInfo::g_bQueryStuHell = true;
	//	return true;
	//}
	//catch (const std::exception&)
	//{
	//	AHPluGinInfo::g_bQueryStuHell = true;
	//	return false;
	//}
}

const bool CodeTool::QueryAHPluGinWorldBoosInfo() {
	return true;
}

const bool CodeTool::IsDefaultBrowsertoIE()
{
	TCHAR szValue[512] = { 0 };
	DWORD dwSize = 512;
	CRegKey reg;
	if (reg.Open(HKEY_CURRENT_USER,
		_T("Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice"),
		KEY_READ) == ERROR_SUCCESS)
	{
		if (reg.QueryStringValue(_T("ProgId"), szValue, &dwSize) == ERROR_SUCCESS)
		{
			if (0 == lstrcmpW(L"IE.HTTP", szValue))
				return true;
		}
		else
			return true;
	}
	else
		return true;
	return false;
}

HINSTANCE CodeTool::ShellExecuteOpenLink(const std::wstring strUrl)
{
	HINSTANCE hRslt = nullptr;
	if (true == IsDefaultBrowsertoIE())
	{
		return ShellExecuteW(NULL, _T("open"), _T("IEXPLORE"), strUrl.c_str(), NULL, SW_SHOWNORMAL);
	}
	hRslt = ShellExecuteW(NULL, _T("open"), strUrl.c_str(), NULL, NULL, SW_SHOWNORMAL);
	if (hRslt <= (HINSTANCE)HINSTANCE_ERROR)
		hRslt = ShellExecuteW(NULL, _T("open"), _T("IEXPLORE"), strUrl.c_str(), NULL, SW_SHOWNORMAL);
	return hRslt;
}

const bool CodeTool::ProcessRunStart(const std::string& strProcessPath, const std::string& strProcessParm) 
{
	PROCESS_INFORMATION pi_work = { 0 };
	STARTUPINFOA si_work = { 0 };
	si_work.cb = sizeof(si_work);
	si_work.wShowWindow = SW_HIDE;
	si_work.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	std::string workMsgPath = strProcessPath;
	if (CreateProcessA(workMsgPath.c_str(), (LPSTR)strProcessParm.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si_work, &pi_work))
	{
		WaitForSingleObject(pi_work.hProcess, 1);
		CloseHandle(pi_work.hProcess);
		CloseHandle(pi_work.hThread);
	}
	else
		return false;
	return true;
}

const bool CodeTool::KillProcess(const std::wstring& strKillName)
{// 指定进程名
	const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (INVALID_HANDLE_VALUE == hSnapshot)
		return false;
	PROCESSENTRY32 pi;
	pi.dwSize = sizeof(PROCESSENTRY32);
	BOOL bRet = Process32First(hSnapshot, &pi);
	while (bRet)
	{
		if (0 == lstrcmpW(strKillName.c_str(), pi.szExeFile))
		{
			const HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.th32ProcessID);
			if (hprocess)
			{
				BOOL ret = TerminateProcess(hprocess, -1);
				CloseHandle(hprocess);
			}
		}
		bRet = Process32Next(hSnapshot, &pi);
	}
	CloseHandle(hSnapshot);
	return true;
}

const bool CodeTool::IsActiveProcess(std::wstring strProcessName)
{
	bool bRet = FALSE;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 process32 = { 0 };
		process32.dwSize = sizeof(process32);

		if (Process32First(hProcessSnap, &process32)) {
			do
			{
				if (_tcsicmp(process32.szExeFile, strProcessName.c_str()) == 0) {
					bRet = TRUE;
					break;
				}
			} while (Process32Next(hProcessSnap, &process32));
		}
		CloseHandle(hProcessSnap);
	}
	return bRet;
}

const bool CodeTool::CGetCurrentDirectory(std::string& strDirpath)
{
	// 获取当前目录路径
	char szModule[1024] = { 0, };
	GetModuleFileNameA(NULL, szModule, sizeof(szModule) / sizeof(char));
	strDirpath = szModule;
	if (0 >= strDirpath.size())
	{
		return 0;
	}
	int offset = strDirpath.rfind("\\");
	if (0 >= offset)
	{
		return 0;
	}
	strDirpath = strDirpath.substr(0, offset + 1);
	return true;
}

// Register
const bool CodeTool::CreateRegEdit(const HKEY rkey, const std::wstring& strKey, const std::wstring& strName, const std::wstring& strValue)
{
	try
	{
		HKEY hKey;
		const HKEY hRoot = rkey;
		const wstring wrKey = strKey.c_str();
		DWORD dwDisposition = REG_CREATED_NEW_KEY;
		LONG lRet = RegCreateKeyEx(
			hRoot,
			wrKey.c_str(),
			0,
			NULL,
			REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY,
			NULL,
			&hKey,
			&dwDisposition
		);
		if (lRet != ERROR_SUCCESS)
			return false;
		lRet = RegSetValueEx(
			hKey,
			strName.c_str(),
			0,
			REG_SZ,
			(LPBYTE)strValue.c_str(),
			sizeof(wchar_t) * strValue.size()
		);
		RegCloseKey(hKey);
		return true;
	}
	catch (...)
	{
		return false;
	}
}

const bool CodeTool::WriteRegValue(const HKEY rkey, const std::wstring& strKey, const std::wstring& strName, const std::wstring& strValue)
{
	try
	{
		HKEY hKey;
		const HKEY hRoot = rkey;
		const wstring wrKey = strKey.c_str();
		DWORD dwDisposition = REG_OPENED_EXISTING_KEY;
		LONG lRet = RegCreateKeyEx(
			hRoot,
			wrKey.c_str(),
			0,
			NULL,
			REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY,
			NULL,
			&hKey,
			&dwDisposition
		);
		if (lRet != ERROR_SUCCESS)
			return false;
		lRet = RegSetValueEx(
			hKey,
			strName.c_str(),
			0,
			REG_SZ,
			(LPBYTE)strValue.c_str(),
			sizeof(wchar_t) * strValue.size()
		);
		RegCloseKey(hKey);
		return true;
	}
	catch (...)
	{
		return false;
	}
}

const bool CodeTool::ReadRegister(const HKEY rkey, const std::string strSubKey, const std::string strKey, OUT std::string& strValue)
{
	try
	{
		char szValue[MAX_PATH] = { 0 }; HKEY hKey = NULL;
#ifdef _WIN32
		LONG ret = RegOpenKeyExA(rkey, strSubKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
#else
		LONG ret = RegOpenKeyExA(rkey, strSubKey.c_str(), 0, KEY_READ, &hKey);
#endif // _WIN32
		if (ret == ERROR_SUCCESS) {
			DWORD dwLen = MAX_PATH;
			ret = RegQueryValueExA(hKey, strKey.c_str(), NULL, NULL, (LPBYTE)szValue, &dwLen);
			if (ret == ERROR_SUCCESS) {
				strValue = szValue;
				if (hKey != NULL)
					RegCloseKey(hKey);
				return true;
			}
		}
		if (hKey != NULL)
			RegCloseKey(hKey);
		return false;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

const bool CodeTool::ReadRegisterDWORD(const HKEY rkey, const std::string strSubKey, const std::string strKey, OUT DWORD64& strValue)
{
	try
	{
		DWORD64 dwReData = 0;; HKEY hKey = NULL;
		LONG ret = RegOpenKeyExA(rkey, strSubKey.c_str(), 0, KEY_READ, &hKey);
		if (ret == ERROR_SUCCESS) {
			DWORD dwLen = MAX_PATH, dwType = REG_DWORD;
			ret = RegQueryValueExA(hKey, strKey.c_str(), NULL, &dwType, (LPBYTE)(&dwReData), &dwLen);
			if (ret == ERROR_SUCCESS) {
				strValue = dwReData;
				if (hKey != NULL)
					RegCloseKey(hKey);
				return true;
			}
		}
		if (hKey != NULL)
			RegCloseKey(hKey);
		return false;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

const bool CodeTool::GetRegisterSteamActiveUser(DWORD64& strUserName)
{
	DWORD64 strValue = 0;
	if (!ReadRegisterDWORD(HKEY_CURRENT_USER, "Software\\Valve\\Steam\\ActiveProcess", "ActiveUser", strValue))
	{
		//OutputDebugStringA(("[PubgAssist] Get PubgActiveUser Register Failuer: " + std::to_string(strValue)).c_str());
		return false;
	}
	if (!strValue)
		return false;
	strUserName = strValue;
	//OutputDebugStringA(("[PubgAssist] Get PubgActiveUser Register Success: " + std::to_string(strValue)).c_str());

	// pid
	//DWORD64 dwPid = 0;
	//if (!ReadRegisterDWORD(HKEY_CURRENT_USER, "Software\\Valve\\Steam\\ActiveProcess", "pid", dwPid))
	//	return false;
	return true;
}

const bool CodeTool::GetRegisterSteamAutoLoginUser(std::string& strLoginUser)
{
	std::string strValue;
	if (ReadRegister(HKEY_CURRENT_USER, "Software\\Valve\\Steam", "AutoLoginUser", strValue)) {
		if (strValue.empty())
			return false;
		strLoginUser = strValue;
		//OutputDebugStringA(("[PubgAssist] Get strLoginUser Register Success: " + strValue).c_str());
		return true;
	}
	return false;
}

const bool CodeTool::GetRegisterSteamPath(std::string& strSteamPath)
{
	std::string strValue;
	if (ReadRegister(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", "InstallPath", strValue)) {
		if (_access(strValue.c_str(), 0) == 0) {
			strSteamPath = strValue;
			return true;
		}
	}

	strValue.clear();
	if (ReadRegister(HKEY_CURRENT_USER, "Software\\Valve\\Steam", "SteamPath", strValue)) {
		if (_access(strValue.c_str(), 0) != 0) {
			return false;
		}
		strSteamPath = strValue;
		return true;
	}

	return false;
}

const bool CodeTool::WriteResourceFile(int resId, LPCTSTR lpszType, LPCTSTR lpszPath)
{
	bool bRet = false;
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(resId), lpszType);
	DWORD dwSize = SizeofResource(NULL, hRsrc);
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	LPVOID pBuffer = LockResource(hGlobal);
	FILE* fp = nullptr;
	errno_t e = _tfopen_s(&fp, lpszPath, _T("wb"));
	if (fp != nullptr)
	{
		fwrite(pBuffer, sizeof(char), dwSize, fp);
		fclose(fp);
		bRet = true;
	}
	return bRet;
}

// File
const bool CodeTool::CreateNewLocalFile(const std::string sFilePath, const std::string& strBuffer) {
	LocalWriteFile(sFilePath, strBuffer);
	return false;
}

const bool CodeTool::LocalReadFile(const std::string sFilePath, std::string& strBuffer) {
	bool bRet = false;
	char* pFileData = nullptr;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = ::CreateFileA(sFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, \
		FILE_ATTRIBUTE_NORMAL, NULL);
	do
	{
		if ((hFile == INVALID_HANDLE_VALUE) || !hFile)
			break;
		DWORD dwFileSize = 0;
		dwFileSize = GetFileSize(hFile, &dwFileSize);
		if (dwFileSize <= 0)
			break;
		pFileData = new char[dwFileSize + 2];
		if (!pFileData)
			break;
		RtlSecureZeroMemory(pFileData, dwFileSize + 2);

		DWORD dwRead = 0;
		::ReadFile(hFile, pFileData, dwFileSize, &dwRead, NULL);
		if (pFileData)
			strBuffer = pFileData;
		bRet = true;

	} while (false);

	if (hFile)
		CloseHandle(hFile);
	if (pFileData) {
		delete[] pFileData;
		pFileData = nullptr;
	}
	if (strBuffer.empty())
		bRet = false;
	return bRet;
}

const bool CodeTool::LocalWriteFile(const std::string sFilePath, const std::string& strBuffer) {
	try
	{
		const HANDLE hFile = ::CreateFileA(sFilePath.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, \
			FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile) {
			DWORD dwWriteSize = 0;
			WriteFile(hFile, strBuffer.c_str(), strBuffer.size(), &dwWriteSize, NULL);
			CloseHandle(hFile);
			return true;
		}
	}
	catch (const std::exception&)
	{
		return false;
	}
	return false;
}

const bool CreateGuid(std::string& strGuid)
{
	char cData[64] = { 0 };
	GUID tGuid;
	if (S_OK == ::CoCreateGuid(&tGuid))
	{
		_snprintf(cData,
			sizeof(cData),
			"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			tGuid.Data1,
			tGuid.Data2,
			tGuid.Data3,
			tGuid.Data4[0],
			tGuid.Data4[1],
			tGuid.Data4[2],
			tGuid.Data4[3],
			tGuid.Data4[4],
			tGuid.Data4[5],
			tGuid.Data4[6],
			tGuid.Data4[7]);
		strGuid = cData;
		return true;
	}
	return false;
}

const bool LoadFromMenu(const int iPackageId, const std::string strExe, std::string strCmd, std::string& error)
{
	typedef long (WINAPI* LPFN_GetPkgIdPath)(unsigned int uGameId, char* szPathBuffer, int nBufferSize);
	
	char path[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA("%windir%\\QueryClientPkgPath.dll", path, MAX_PATH);
	HMODULE hDll = LoadLibraryA(path);
	if (NULL == hDll)
	{
		error = "Cannot Find File : QueryClientPkgPath.dll";
		return false;
	}

	LPFN_GetPkgIdPath fnQuery = (LPFN_GetPkgIdPath)GetProcAddress(hDll, "GetGamePathByPackageID");
	if (NULL == fnQuery)
	{
		error = "Cannot Find Function : GetGamePathByPackageID";
		FreeLibrary(hDll);
		return false;
	}
	RtlSecureZeroMemory(path, sizeof(path));
	long nResult = fnQuery(iPackageId, path, MAX_PATH);
	char* pos = strrchr(path, '\\');
	if (pos)
	{
		*(pos + 1) = 0;
		lstrcatA(path, strExe.c_str());
	}
	else
		return false;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof si);
	ZeroMemory(&pi, sizeof pi);
	si.cb = sizeof si;
	if (CreateProcessA(path, (char*)strCmd.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return true;
	}
	error = std::string("Create Process Failed ").append(path).append(" - ").append(to_string(GetLastError()));
	return false;
}