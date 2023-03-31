#pragma once

#include "wincng_crypt.h"

wincng_aeskey_ctx_t wincng_aeskey_ctx_new(const unsigned char *key, size_t key_size, const unsigned char *iv, size_t iv_size);

int wincng_ran_byte();

void wincng_aeskey_ctx_free(wincng_aeskey_ctx_t ctx);
