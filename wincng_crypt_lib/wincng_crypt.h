#pragma once

#include <Windows.h>

typedef struct wincng_aeskey_ctx {
	const unsigned char *shared_secret_key;
	size_t shared_secret_key_size;
	unsigned char *pbIV;
	size_t cbIV;

	BCRYPT_ALG_HANDLE       hAesAlg;


	PUCHAR pbKeyObject;
	ULONG  cbKeyObject;

	BCRYPT_KEY_HANDLE       hKey;

} *wincng_aeskey_ctx_t;

#include "wincng_aeskey.h"
