#include <mysql.h>
#include <string.h>
#include <stdio.h>

#include <gmp.h>
#define DeclareAndInit(n) mpz_t n; mpz_init(n)

#include <libcry.h>

struct CryptoBlock
{
    elgamal_public_key *pk;
    elgamal_private_key *vk;
    hcs_random *hr;
    elgamal_cipher *rcip;
};

unsigned long ElgamalMultiplicationAggregate(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
my_bool ElgamalMultiplicationAggregate_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void ElgamalMultiplicationAggregate_deinit(UDF_INIT *initid);
void ElgamalMultiplicationAggregate_reset(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);
void ElgamalMultiplicationAggregate_clear(UDF_INIT *initid, char *is_null, char *error);
void ElgamalMultiplicationAggregate_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);


unsigned long ElgamalMultiplicationAggregate(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    unsigned long x;
    DeclareAndInit(X);

    struct CryptoBlock *crypto = (struct CryptoBlock*) initid->ptr;
    elgamal_decrypt(crypto->vk, X, crypto->rcip);
    x = mpz_get_ui(X);

    mpz_clear(X);

    return x;
}

my_bool ElgamalMultiplicationAggregate_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    struct CryptoBlock *crypto;
    initid->maybe_null = 0;
    
    if (args->arg_count != 1 || args->arg_type[0] != INT_RESULT)
    {
        strcpy(message, "Elgamal aggregate requires an argument of type [INT]");
        return 1;
    }

    if (!(crypto = (struct CryptoBlock*)malloc(sizeof(struct CryptoBlock))))
    {
        strcpy(message, "Elgamal aggregate couldn't allocate memory");
        return 1;
    }
    
    DeclareAndInit(t1);
    mpz_set_ui(t1, 1);

    crypto->pk = elgamal_init_public_key();
    crypto->vk = elgamal_init_private_key();
    crypto->hr = hcs_init_random();
    crypto->rcip = elgamal_init_cipher();

    elgamal_generate_key_pair(crypto->pk, crypto->vk, crypto->hr, 2048);
    elgamal_encrypt(crypto->pk, crypto->hr, crypto->rcip, t1);

    initid->ptr = (char*) crypto;

    mpz_clear(t1);

    return 0;
}

void ElgamalMultiplicationAggregate_reset(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    ElgamalMultiplicationAggregate_clear(initid, is_null, error);
    ElgamalMultiplicationAggregate_add(initid, args, is_null, error);
}

void ElgamalMultiplicationAggregate_clear(UDF_INIT *initid, char *is_null, char *error)
{
    struct CryptoBlock *crypto = (struct CryptoBlock*)initid->ptr;

    mpz_t t1;
    mpz_init_set_ui(t1, 1);

    elgamal_cipher *op = elgamal_init_cipher();
    elgamal_encrypt(crypto->pk, crypto->hr, op, t1);
    elgamal_set(crypto->rcip ,op);

    mpz_clear(t1);
}

void ElgamalMultiplicationAggregate_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    if(args->args[0])
    {
        struct CryptoBlock* crypto = (struct CryptoBlock*) initid->ptr;
        long long int x = *((long long int*) args->args[0]);

        DeclareAndInit(X);
        mpz_set_ui(X, x);

        elgamal_cipher *ca = elgamal_init_cipher();
        elgamal_encrypt(crypto->pk, crypto->hr, ca, X);
        elgamal_ee_mul(crypto->pk, crypto->rcip, crypto->rcip, ca);

        mpz_clear(X);
    }
}

void ElgamalMultiplicationAggregate_deinit(UDF_INIT *initid)
{
    if(initid->ptr != NULL)
    {
        struct CryptoBlock* crypto = (struct CryptoBlock*) initid->ptr;
        elgamal_free_public_key(crypto->pk);
        elgamal_free_private_key(crypto->vk);
        elgamal_free_cipher(crypto->rcip);
        hcs_free_random(crypto->hr);
    }
}

