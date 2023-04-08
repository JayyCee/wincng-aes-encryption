#include <Windows.h>
#include <assert.h>

#include "base64_proc.h"

int base64_encode(const unsigned char *in_data, size_t in_data_size, const char **out_data_p, size_t *out_data_size_p)
{
	int retv_exit = 0;
	int retv;
	DWORD base64_str_size = 0;

	// calculate the size of the buffer to hold base64 string
	retv = CryptBinaryToStringA(
		in_data, //pbBinary,
		(DWORD)in_data_size, // cbBinary,
		CRYPT_STRING_BASE64HEADER | CRYPT_STRING_NOCR, // CRYPT_STRING_BASE64,
		NULL, // pszString, NULL for calculating the base64_str_size
		&base64_str_size //pcchString
	);

	assert(retv);

	char *base64_str_buf = malloc(base64_str_size);

	if (base64_str_buf == NULL) {
		retv_exit = -1;
		goto done;
	}

	// rturn TRUE on success
	retv = CryptBinaryToStringA(
		in_data, //pbBinary,
		(DWORD)in_data_size, // cbBinary,
		CRYPT_STRING_BASE64HEADER | CRYPT_STRING_NOCR, // CRYPT_STRING_BASE64,
		base64_str_buf, // pszString
		&base64_str_size //pcchString
	);

	if (!retv) {
		retv_exit = -1;
		goto done;
	}

	*out_data_p = (const char *)base64_str_buf;

	*out_data_size_p = base64_str_size;

done:

	return retv_exit;
}


int base64_decode(const char *in_data, size_t in_data_size, const unsigned char **out_data_p, size_t *out_data_size_p)
{
	int retv_exit = 0;
	int retv;
	DWORD decoded_buf_size = 0;

	// calculate the size of the buffer to hold decoded data

	retv = CryptStringToBinaryA(
		in_data,              // pszString,
		(DWORD)in_data_size,         // cchString,
		CRYPT_STRING_BASE64HEADER, // CRYPT_STRING_BASE64,  // dwFlags,
		NULL,  // pbBinary,
		&decoded_buf_size, // pcbBinary,
		NULL, // pdwSkip,
		NULL  // pdwFlags
	);

	assert(retv);

	unsigned char *decoded_data_buf = malloc(decoded_buf_size);

	if (decoded_data_buf == NULL) {
		retv_exit = -1;
		goto done;
	}

	// rturn TRUE on success
	retv = CryptStringToBinaryA(
		in_data,              // pszString,
		(DWORD)in_data_size,         // cchString,
		CRYPT_STRING_BASE64HEADER, // CRYPT_STRING_BASE64,  // dwFlags,
		decoded_data_buf,  // pbBinary,
		&decoded_buf_size, // pcbBinary,
		NULL, // pdwSkip,
		NULL  // pdwFlags
	);

	if (!retv) {
		retv_exit = -1;
		goto done;
	}

	*out_data_p = decoded_data_buf;

	*out_data_size_p = decoded_buf_size;

done:

	return retv_exit;
}
