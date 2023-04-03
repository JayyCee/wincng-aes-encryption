#define UMDF_USING_NTSTATUS

#include <windows.h>
#include <assert.h>
#include <ntstatus.h>
#include <assert.h>
#include <stdio.h>

#include "wincng_crypt.h"

#include "wincng_aes.h"

#define MY_LOG(...) do {int line = __LINE__;\
	printf("%s:%d: ", __FILE__, line);\
	printf(__VA_ARGS__); \
} while (0)

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

static const char *wincng_get_ntstat_s_by_v(NTSTATUS v);


wincng_aes_ctx_t wincng_aes_ctx_new(const unsigned char *shared_secret_key, size_t shared_secret_key_size)
{
	wincng_aes_ctx_t ctx = NULL;
	ctx = calloc(1, sizeof(*ctx));

	if (!ctx)
		goto done;

	// fill in struct data
	ctx->shared_secret_key = shared_secret_key;
	ctx->shared_secret_key_size = shared_secret_key_size;
	

	
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
	ULONG cbResult = 0;

	if (!NT_SUCCESS(status = BCryptGetProperty(
		ctx->hAesAlg,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&(ctx->cbKeyObject),
		sizeof(ctx->cbKeyObject),
		&cbResult,
		0)))
	{
		MY_LOG("** Error: BCryptGetProperty(): 0x%08X: %s\n", status, wincng_get_ntstat_s_by_v(status));
		goto done_err;
	}


	// Allocate the keyObject
	// keyobject takes data when hKey is generated
	ctx->pbKeyObject = malloc(ctx->cbKeyObject);
	if (NULL == ctx->pbKeyObject)
	{
		goto done_err;
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

	// Generate the hKey and keyObject from supplied input key bytes.
	if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
		ctx->hAesAlg,
		&ctx->hKey,
		ctx->pbKeyObject,
		ctx->cbKeyObject,
		(PBYTE)shared_secret_key,
		(ULONG)shared_secret_key_size,
		0)))
	{
		printf("**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
		goto done_err;
	}

	// All is good now
	goto done;

done_err:
	if (ctx) {
		wincng_aes_ctx_free(ctx);
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


void wincng_aes_ctx_free(wincng_aes_ctx_t ctx)
{
	if (ctx == NULL)
		return;


	if (ctx->pbKeyObject) {
		free(ctx->pbKeyObject);
		ctx->pbKeyObject = NULL;
	}

	if (ctx->hKey) {
		BCryptDestroyKey(ctx->hKey);
	}

	if (ctx->hAesAlg) {
		BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);
		ctx->hAesAlg = NULL;
	}

	free(ctx);

}

struct ntstat_v_s {
	LONG v;
	const char *s;
};

static struct  ntstat_v_s sg_ntstat_v_s[] = {
	STATUS_BUFFER_TOO_SMALL, "STATUS_BUFFER_TOO_SMALL",
	STATUS_DATA_ERROR, "STATUS_DATA_ERROR",
};

static const char *wincng_get_ntstat_s_by_v(NTSTATUS v)
{
	int i;

	static const char unknown[] = "unknown";

	for (i = 0; i < ARRAYSIZE(sg_ntstat_v_s); i++) {
		if (sg_ntstat_v_s[i].v == v)
			return sg_ntstat_v_s[i].s;
	}

	return unknown;
}


static int wincng_aes_iv_gen(unsigned char **iv_pp, size_t *iv_size_p)
{
	int retv_exit = 0;
	int i;

#define IV_SIZE 16

	unsigned char *iv_p = malloc(IV_SIZE);
	assert(iv_p);

	for (i = 0; i < IV_SIZE; i++) {
		iv_p[i] = (unsigned char)wincng_ran_byte();
	}

	*iv_pp = iv_p;
	*iv_size_p = IV_SIZE;

	return retv_exit;
}



int wincng_aes_encrypt(
	wincng_aes_ctx_t ctx,
	const unsigned char *plaintext_p, size_t plaintext_size,
	const unsigned char **ciphertext_pp, size_t *ciphertext_size_p,
	const unsigned char **iv_pp, size_t *iv_size_p
)

{
	int retv_exit = 0;
	int retv;

	NTSTATUS status;
	ULONG cbResult = 0;
	PUCHAR pbIV_tmp = NULL;
	ULONG cbIV_tmp;

	unsigned char *iv_p;
	size_t iv_size;

	retv = wincng_aes_iv_gen(&iv_p, &iv_size);
	if (retv != 0) {
		MY_LOG("wincng_aes_iv_gen() failed.");
	}
	assert(retv == 0);

	pbIV_tmp = malloc(iv_size);
	assert(pbIV_tmp);


	// Calculate the block length for the IV.
	if (!NT_SUCCESS(status = BCryptGetProperty(
		ctx->hAesAlg,
		BCRYPT_BLOCK_LENGTH,   //JC: this does not seem to have anything related to the IV?
		(PBYTE)&cbIV_tmp,
		sizeof(cbIV_tmp),
		&cbResult,
		0)))
	{
		printf("**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto done_err;
	}

	// Determine whether the cbIV is not longer than the IV length.
	if (cbIV_tmp > iv_size)
	{
		printf("**** block length is longer than the provided IV length\n");
		goto done_err;
	}

	memcpy(pbIV_tmp, iv_p, iv_size);


	//
	// find out the output ciphertext buffer size.
	//
	ULONG cbCiphertext;

	if (!NT_SUCCESS(status = BCryptEncrypt(
		ctx->hKey,
		(PUCHAR)plaintext_p,
		(ULONG)plaintext_size,
		NULL,
		pbIV_tmp,
		cbIV_tmp,
		NULL,
		0,
		&cbCiphertext,
		BCRYPT_BLOCK_PADDING)))
	{
		printf("**** Error 0x%x returned by BCryptEncrypt\n", status);
		goto done_err;
	}

	unsigned char *pbCiphertext = malloc(cbCiphertext);
	if (NULL == pbCiphertext)
	{
		printf("**** memory allocation failed\n");
		goto done_err;
	}

	// Use the key to encrypt the plaintext buffer.
	// For block sized messages, block padding will add an extra block.
	if (!NT_SUCCESS(status = BCryptEncrypt(
		ctx->hKey,
		(PUCHAR)plaintext_p,
		(ULONG)plaintext_size,
		NULL,        //JC: the padding is not needed here
		pbIV_tmp,
		cbIV_tmp,
		pbCiphertext,
		cbCiphertext,
		&cbCiphertext,
		BCRYPT_BLOCK_PADDING)))
	{
		printf("**** Error 0x%x returned by BCryptEncrypt\n", status);
		goto done_err;
	}

	
	*iv_pp = iv_p;
	*iv_size_p = iv_size;
	*ciphertext_pp = pbCiphertext;
	*ciphertext_size_p = cbCiphertext;

	goto done;

done_err:
	retv_exit = -1;

done:
	if (pbIV_tmp)
		free(pbIV_tmp);

	return retv_exit;

}


int wincng_aes_decrypt(
	wincng_aes_ctx_t ctx,
	unsigned char *iv_p, size_t iv_size,
	unsigned char *ciphertext_p, size_t ciphertext_size,
	unsigned char **decrypted_data_pp, size_t *decrypted_data_size_p
)
{
	int retv_exit = 0;

	NTSTATUS status;



	// Reinitialize a temp IV because encryption would have modified the original.

	DWORD cbIV_tmp = (DWORD)iv_size;
	PUCHAR pbIV_tmp = malloc(cbIV_tmp);
	assert(pbIV_tmp);

	memcpy(pbIV_tmp, iv_p, cbIV_tmp);


	//
	// Get the plaintext output buffer size.
	//

	ULONG cbPlaintext = 0;
	PUCHAR pbPlaintext = NULL;

	if (!NT_SUCCESS(status = BCryptDecrypt(
		ctx->hKey,
		(PUCHAR)ciphertext_p,
		(ULONG)ciphertext_size,
		NULL,
		pbIV_tmp,
		cbIV_tmp,
		NULL,
		0,
		&cbPlaintext,
		BCRYPT_BLOCK_PADDING)))
	{
		printf("**** Error 0x%x returned by BCryptDecrypt\n", status);
		goto done_err;
	}

	pbPlaintext = malloc(cbPlaintext);
	assert(pbPlaintext);


	// now do real descryption

	if (!NT_SUCCESS(status = BCryptDecrypt(
		ctx->hKey,
		(PUCHAR)ciphertext_p,
		(ULONG)ciphertext_size,
		NULL,
		pbIV_tmp,
		cbIV_tmp,
		pbPlaintext,
		cbPlaintext,
		&cbPlaintext,
		BCRYPT_BLOCK_PADDING)))
	{
		MY_LOG("** Error: BCryptDecrypt(): 0x%08X: %s\n", status, wincng_get_ntstat_s_by_v(status));
		goto done_err;
	}

	// all is good now
	*decrypted_data_pp = pbPlaintext;
	*decrypted_data_size_p = cbPlaintext;
	goto done;

done_err:
	retv_exit = -1;

done:

	if (pbIV_tmp)
		free(pbIV_tmp);

	return retv_exit;

}

