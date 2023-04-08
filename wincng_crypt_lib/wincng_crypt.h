#pragma once

#include <Windows.h>

typedef struct wincng_aes_ctx {
	const unsigned char *shared_secret_key;
	size_t shared_secret_key_size;
	BCRYPT_ALG_HANDLE       hAesAlg;
	BCRYPT_KEY_HANDLE       hKey;

} *wincng_aes_ctx_t;

#include "wincng_aes.h"

#include "base64_proc.h"
