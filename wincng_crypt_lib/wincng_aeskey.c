#define UMDF_USING_NTSTATUS

#include <windows.h>
#include <assert.h>
#include <ntstatus.h>


#include "wincng_crypt.h"

#include "wincng_aeskey.h"

static const unsigned char key_iv[] = {
	131,  67, 200,  76, 149, 200,  28,  51,
	246, 166,  84, 193,  22, 190, 161, 169
};

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


wincng_aeskey_ctx_t wincng_aeskey_ctx_new(const unsigned char *shared_secret_key, size_t shared_secret_key_size, const unsigned char *iv, size_t iv_size)
{
	wincng_aeskey_ctx_t ctx = NULL;
	ctx = calloc(1, sizeof(*ctx));

	if (!ctx)
		goto done;

	// fill in struct data
	ctx->shared_secret_key = shared_secret_key;
	ctx->shared_secret_key_size = shared_secret_key_size;
	ctx->pbIV = iv;
	ctx->cbIV = iv_size;

	
	NTSTATUS status;

	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&ctx->hAesAlg,
		BCRYPT_AES_ALGORITHM,  // AES symetric encryption algorithm
		NULL, // NULL is for using default provider
		0)))
	{
		ctx = NULL;
		goto done_err;
	}

	// Calculate the size of the buffer to hold the KeyObject.
	DWORD cbData = 0;

	if (!NT_SUCCESS(status = BCryptGetProperty(
		ctx->hAesAlg,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&ctx->cbKeyObject,
		sizeof(ctx->cbKeyObject),
		&cbData,
		0)))
	{
		goto done_err;
	}

	// Allocate the key object on the heap.
	ctx->pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ctx->cbKeyObject);
	if (NULL == ctx->pbKeyObject)
	{
		goto done_err;
	}



done_err:
	if (ctx->hAesAlg)
		BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);

	if (ctx) {
		free(ctx);
		ctx = NULL;
	}

done:

	return ctx;
}

int wincng_aeskey_ctx_set_keybyte(const unsigned char *key_byte_data, size_t key_byte_data_size, wincng_aeskey_ctx_t *wincng_aeskey_ctx_p)
{
	int retv_exit = 0;


	key_byte_data;
	key_byte_data_size;
	wincng_aeskey_ctx_p;



	return retv_exit;
}

int wincng_ran_byte()
{
	BCRYPT_ALG_HANDLE hAlgRan;

	NTSTATUS ns = BCryptOpenAlgorithmProvider(
		&hAlgRan,
		BCRYPT_RNG_ALGORITHM,
		NULL, // use system default pszImplementation,
		0
	);

	assert(ns == STATUS_SUCCESS);

	unsigned char buf[1];
	ns = BCryptGenRandom(
		hAlgRan,
		&buf[0],
		sizeof(buf),
		0
	);

	assert(ns == STATUS_SUCCESS);

	return buf[0];
}