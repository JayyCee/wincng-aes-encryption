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

	unsigned char shared_aes_iv_arrary[] = {
		163, 210, 138,  47,  42,  64, 194,  92,
		48, 198,  97, 198, 198,   0, 100,  86
	};

	wincng_aes_ctx_t aes_ctx = NULL;


	// JC todo: remove IV here:
	aes_ctx = wincng_aes_ctx_new(
		&shared_aes_secret_array[0],
		sizeof(shared_aes_secret_array)
	);

	assert(aes_ctx);

	//JC todo: encryption with a new IV:
	// 
	unsigned char *iv_p = NULL;
	size_t iv_size = 0;
	const unsigned char plaintext[] = "JC message!";
	const unsigned char *ciphertext_p = NULL;
	size_t ciphertext_size = 0;

	retv = wincng_aes_encrypt(
		aes_ctx,
		plaintext, sizeof(plaintext),
		&ciphertext_p, &ciphertext_size,
		&iv_p, &iv_size
	);

	assert(retv == 0);

	wincng_aes_ctx_free(aes_ctx);

	return 0;
}
