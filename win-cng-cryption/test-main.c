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

	const char plaintext[] = "This is JC's plaintext data!";
	const unsigned char *ciphertext_p = NULL;
	size_t ciphertext_size = 0;

	const unsigned char shared_aeskey_secret_array[] = {
		113,  77,   4, 200, 210, 172, 225, 192,
		130,  46, 250,   0, 151, 255, 179,  88
	};

	unsigned char shared_aeskey_iv_arrary[] = {
		163, 210, 138,  47,  42,  64, 194,  92,
		48, 198,  97, 198, 198,   0, 100,  86
	};

	wincng_aeskey_ctx_t aeskey_encrypt_ctx = NULL;

	int i;

	for (i = 0; i < 16; i++) {
		shared_aeskey_iv_arrary[i] = wincng_ran_byte();
		printf("ran = % d\n", shared_aeskey_iv_arrary[i]);
	}

	aeskey_encrypt_ctx = wincng_aeskey_ctx_new(
		&shared_aeskey_secret_array[0],
		sizeof(shared_aeskey_secret_array),
		&shared_aeskey_iv_arrary[0],
		sizeof(shared_aeskey_iv_arrary)
	);
	assert(aeskey_encrypt_ctx);

	//retv = wincng_aeskey_ctx_new(&aeskey_byte_array[0], sizeof(aeskey_byte_array), &aeskey_ctx);

	//retv = wincng_crypt_aes_encrypt(&aeskey_ctx, plaintext, sizeof(plaintext), &ciphertext_p, &ciphertext_size);

	assert(retv == 0);

	wincng_aeskey_ctx_free(aeskey_encrypt_ctx);

	return 0;
}
