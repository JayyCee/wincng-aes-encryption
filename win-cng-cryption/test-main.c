// win-cng-cryption.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#pragma warning(disable : 4996)


#include <Windows.h>
#include <stdio.h>
#include <assert.h>

#include "wincng_crypt.h"

#pragma comment (lib, "Bcrypt.lib")
#pragma comment (lib, "wincng_crypt_lib.lib")
#pragma comment (lib, "Crypt32.lib")  // for base64 function



int main(int argc, const char *argv[])
{
	int retv_exit = 0;
	int retv = 0;


	printf("%s is running ...\n", argv[0]);

	const unsigned char shared_aes_secret_array[] = {
		113,  77,   4, 200, 210, 172, 225, 192,
		130,  46, 250,   0, 151, 255, 179,  88
	};


	wincng_aes_ctx_t aes_ctx = NULL;

	aes_ctx = wincng_aes_ctx_new(
		shared_aes_secret_array,
		sizeof(shared_aes_secret_array)
	);

	assert(aes_ctx);

	unsigned char *iv_p = NULL;
	size_t iv_size = 0;
	const unsigned char plaintext[] = "abcdefghijklmnopABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned char *ciphertext_p = NULL;
	size_t ciphertext_size = 0;

	retv = wincng_aes_encrypt(
		aes_ctx,
		plaintext, sizeof(plaintext),
		&ciphertext_p, &ciphertext_size,
		&iv_p, &iv_size
	);

	assert(retv == 0);

	wincng_aes_ctx_free(aes_ctx);
	aes_ctx = NULL;

	// prefix VI to encrypted data
	// 
	unsigned char *total_data_buf = NULL;
	size_t total_data_buf_size = iv_size + ciphertext_size;

	total_data_buf = (unsigned char *)malloc(total_data_buf_size);

	assert(total_data_buf);

	memcpy(total_data_buf, iv_p, iv_size);
	memcpy(total_data_buf + iv_size, ciphertext_p, ciphertext_size);

// ----- Write to file ------
// 
	const char *encrypt_filename = "my_encrypt.out";

	FILE *fp_out = fopen(encrypt_filename, "w");

	if (fp_out == NULL) {
		printf("fopen(%s) failed: %s\n", encrypt_filename, strerror(errno));
		retv_exit = 1;
		goto done;
	}

	// base64
	const char *base64_buf_p;
	size_t base64_buf_size;

	retv = base64_encode(total_data_buf, total_data_buf_size, &base64_buf_p, &base64_buf_size);

	size_t nw = fwrite(base64_buf_p, 1, base64_buf_size, fp_out);

	assert(nw == base64_buf_size);

	if (fp_out) {
		fclose(fp_out);
		fp_out = NULL;
	}


	// ============== DO Decryption ===============

	aes_ctx = wincng_aes_ctx_new(
		shared_aes_secret_array,
		sizeof(shared_aes_secret_array)
	);

	assert(aes_ctx);

	unsigned char *decrypted_data_p = NULL;
	size_t decrypted_data_size = 0;

	retv = wincng_aes_decrypt(
		aes_ctx,
		iv_p, iv_size,
		ciphertext_p, ciphertext_size,
		&decrypted_data_p, &decrypted_data_size
	);

	assert(retv == 0);

	// everything is done, do cleanups
	wincng_aes_ctx_free(aes_ctx);
	aes_ctx = NULL;

	if (decrypted_data_p) {
		free(decrypted_data_p);
		decrypted_data_p = NULL;
	}
	
	if (ciphertext_p) {
		free(ciphertext_p);
		ciphertext_p = NULL;
	}

	if (iv_p) {
		free(iv_p);
		iv_p = NULL;
	}

done:

	return 0;
}
