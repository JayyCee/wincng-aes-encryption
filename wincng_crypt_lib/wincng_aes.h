#pragma once

#include "wincng_crypt.h"

wincng_aes_ctx_t wincng_aes_ctx_new(const unsigned char *key, size_t key_size);

int wincng_ran_byte();

void wincng_aes_ctx_free(wincng_aes_ctx_t ctx);

int wincng_aes_encrypt(wincng_aes_ctx_t ctx,
	const unsigned char *plaintext_p, size_t plaintext_size,
	const unsigned char **ciphertext_pp, size_t *ciphertext_size_p,
	const unsigned char **iv_pp, size_t *iv_size_p
);
