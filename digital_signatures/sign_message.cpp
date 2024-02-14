#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define KEYFILE "private_key.pem"
#define N 3000
#define BUFFSIZE 80

EVP_PKEY *read_secret_key_from_file(const char * fname)
{
    EVP_PKEY *key = NULL;
    FILE *fp = fopen(fname, "r");
    if(!fp) {
        perror(fname); return NULL;
    }
    key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

int do_sign(EVP_PKEY *key, const unsigned char *msg, const size_t mlen,
            void **sig, size_t *slen)
{
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;

    /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_create())) goto err;

    /* Initialise the DigestSign operation - SHA-256 has been selected
     * as the message digest function in this example */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key))
        goto err;

    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mdctx, msg, mlen)) goto err;

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to
     * obtain the length of the signature. Length is returned in slen */
    if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)) goto err;
    /* Allocate memory for the signature based on size in slen */
    if(!(*sig = OPENSSL_malloc(*slen))) goto err;
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx, (unsigned char*) *sig, slen)) goto err;

    /* Success */
    ret = 1;

err:
    if(ret != 1)
    {
        /* Do some error handling */
    }

    /* Clean up */
    if(*sig && !ret) OPENSSL_free(*sig);
    if(mdctx) EVP_MD_CTX_destroy(mdctx);

    return ret;
}

int main()
{
    int ret = EXIT_FAILURE;
    const char *str = "I am watching you!I am watching you!";
    void *sig = NULL;
    size_t slen = 0;
    unsigned char msg[BUFFSIZE];
    size_t mlen = 0;

    EVP_PKEY *key = read_secret_key_from_file(KEYFILE);
    if(!key) goto err;

    for(int i=0;i<N;i++) {
        if ( snprintf((char *)msg, BUFFSIZE, "%s %d", str, i+1) < 0 )
            goto err;
        mlen = strlen((const char*)msg);
        if (!do_sign(key, msg, mlen, &sig, &slen)) goto err;
        OPENSSL_free(sig); sig = NULL;
        printf("\"%s\" -> siglen=%lu\n", msg, slen);
    }

    printf("DONE\n");
    ret = EXIT_SUCCESS;

err:
    if (ret != EXIT_SUCCESS) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Something broke!\n");
    }

    if (key)
        EVP_PKEY_free(key);

    exit(ret);
}

