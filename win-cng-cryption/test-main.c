// win-cng-cryption.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <assert.h>

#include "wincng_crypt.h"

#pragma comment (lib, "Bcrypt.lib")
#pragma comment (lib, "wincng_crypt_lib.lib")



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

	return 0;
}
