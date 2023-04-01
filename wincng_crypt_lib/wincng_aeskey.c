#define UMDF_USING_NTSTATUS

#include <windows.h>
#include <assert.h>
#include <ntstatus.h>
#include <assert.h>


#include "wincng_crypt.h"

#include "wincng_aeskey.h"


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
	
	// make a copy of IV
	ctx->pbIV = malloc(iv_size);
	assert(ctx->pbIV);

	memcpy(ctx->pbIV, iv, iv_size);
	ctx->cbIV = iv_size;

	
	NTSTATUS status;

	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&ctx->hAesAlg,
		BCRYPT_AES_ALGORITHM,  // AES symetric encryption algorithm
		NULL, // NULL is for using default provider
		0)))
	{
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


	// Calculate the block length for the IV.
	if (!NT_SUCCESS(status = BCryptGetProperty(
		ctx->hAesAlg,
		BCRYPT_BLOCK_LENGTH,   //JC: this does not seem to have anything related to the IV?
		(PBYTE)&ctx->cbIV,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		printf("**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto done_err;
	}

	// Determine whether the cbIV is not longer than the IV length.
	if (ctx->cbIV > iv_size)
	{
		printf("**** block length is longer than the provided IV length\n");
		goto done_err;
	}

	// Allocate a buffer for the IV. The buffer is consumed during the 
// encrypt/decrypt process.
	ctx->pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ctx->cbIV);
	if (NULL == ctx->pbIV)
	{
		printf("**** memory allocation failed\n");
		goto done_err;
	}

	memcpy(ctx->pbIV, iv, ctx->cbIV);


	if (ctx->hAesAlg)
		BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);

	if (ctx) {
		wincng_aeskey_ctx_free(ctx);
		ctx = NULL;
	}

	// CNG API needs us to choose a mode: CBC mode is recommeded
	if (!NT_SUCCESS(status = BCryptSetProperty(
		ctx->hAesAlg,
		BCRYPT_CHAINING_MODE,
		(PBYTE)BCRYPT_CHAIN_MODE_CBC,
		sizeof(BCRYPT_CHAIN_MODE_CBC),
		0)))
	{
		printf("**** Error 0x%x returned by BCryptSetProperty\n", status);
		goto done_err;
	}

	// Generate the keyObject from supplied input key bytes.
	if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
		ctx->hAesAlg,
		&ctx->hKey,
		ctx->pbKeyObject,
		ctx->cbKeyObject,
		(PBYTE)shared_secret_key,
		shared_secret_key_size,
		0)))
	{
		printf("**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
		goto done_err;
	}

	// All is good now
	goto done;

done_err:
	if (ctx) {
		wincng_aeskey_ctx_free(ctx);
		ctx = NULL;
	}

done:

	return ctx;
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


void wincng_aeskey_ctx_free(wincng_aeskey_ctx_t ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->pbIV)
		free(ctx->pbIV);
	
	BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);
		

	free(ctx);

}