#include <stdio.h>
#include "relic.h"
#include "sm2.h"
#include "debug.h"

static ep_t SM2_G;
static fp_t SM2_N;
static fp_t SM2_ONE;

int sm2_do_sign_ex(const SM2_KEY *key, int fixed_outlen, const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
//    SM2_JACOBIAN_POINT _P, *P = &_P;
    ep_t P;

    fp_t d;
    fp_t e;
    bn_t k_bn;
    fp_t k_fp;
    uint8_t k_bin[64];
    fp_t x;
    fp_t r;
    fp_t s;

    retry:
//    sm2_bn_from_bytes(d, key->private_key);
    fp_read_bin(d, key->private_key, 32);

    // e = H(M)
//    sm2_bn_from_bytes(e, dgst);	//print_bn("e", e);
    fp_read_bin(e, dgst, 32);
    // e被重用了，注意retry的位置！

    // rand k in [1, n - 1]
    do {
//        sm2_fn_rand(k);
        bn_rand(k_bn, RLC_POS, 32);
//    } while (sm2_bn_is_zero(k));
    } while (bn_is_zero(k_bn));

    //print_bn("k", k);

    // (x, y) = kG
//    sm2_jacobian_point_mul_generator(P, k);
//    sm2_jacobian_point_get_xy(P, x, NULL);
    ep_mul_basic(P, SM2_G, k_bn);
    ep_norm(P, P);
    fp_copy(x, P->x);
    //print_bn("x", x);
    bn_write_bin(k_bin, 64, k_bn);
    fp_read_bin(k_fp, k_bin, 64);

    // r = e + x
    fp_add(r, e, x);		//print_bn("r = e + x (mod n)", r);


    /* if r == 0 or r + k == n re-generate k */
//    if (sm2_bn_is_zero(r)) {
    if (fp_is_zero(r)) {
        goto retry;
    }
    fp_add(x, r, k_fp);
    if (fp_cmp(x, SM2_N) == 0) {
        goto retry;
    }

    /* s = ((1 + d)^-1 * (k - r * d)) mod n */

    fp_mul(e, r, d);		//print_bn("r*d", e);
    fp_sub(k_fp, k_fp, e);		//print_bn("k-r*d", k);
    fp_add(e, SM2_ONE, d);	//print_bn("1 +d", e);
    fp_inv(e, e);		//print_bn("(1+d)^-1", e);
    fp_mul(s, e, k_fp);		//print_bn("s = ((1 + d)^-1 * (k - r * d)) mod n", s);

    fp_write_bin(sig->r, 32, r);
    fp_write_bin(sig->s, 32, s);
//
//    sm2_bn_to_bytes(r, sig->r);	//print_bn("r", r);
//    sm2_bn_to_bytes(s, sig->s);	//print_bn("s", s);

//    if (fixed_outlen) {
//        uint8_t buf[72];
//        uint8_t *p = buf;
//        size_t len = 0;
//        sm2_signature_to_der(sig, &p, &len);
//        if (len != 71) {
//            goto retry;
//        }
//    }

//    gmssl_secure_clear(d, sizeof(d));
//    gmssl_secure_clear(e, sizeof(e));
//    gmssl_secure_clear(k, sizeof(k));
//    gmssl_secure_clear(x, sizeof(x));
    return 1;
}


int sm2_sign_ex(const SM2_KEY *key, int fixed_outlen, const uint8_t dgst[32], uint8_t *sig, size_t *siglen)
{
    SM2_SIGNATURE signature;
    uint8_t *p;

    if (!key
        || !dgst
        || !sig
        || !siglen) {
        error_print();
        return -1;
    }

    p = sig;
    *siglen = 0;
//    if (sm2_do_sign_ex(key, fixed_outlen, dgst, &signature) != 1
//        || sm2_signature_to_der(&signature, &p, siglen) != 1) {
    if (sm2_do_sign_ex(key, fixed_outlen, dgst, &signature) != 1) {
        error_print();
        return -1;
    }
    return 1;
}

int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen)
{
    return sm2_sign_ex(key, 0, dgst, sig, siglen);
}

int sm2_compute_z(uint8_t z[32], const ep_t pub, const char *id, size_t idlen)
{
    SM3_CTX ctx;
    uint8_t zin[18 + 32 * 6] = {
            0x00, 0x80,
            0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
            0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
            0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
            0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
            0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
            0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
            0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
            0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
    };

    if (!z || !pub || !id) {
        error_print();
        return -1;
    }


    ep_write_bin(&zin[18 + 32 * 4], 64, pub, 0);


//    memcpy(&zin[18 + 32 * 4], pub->x, 32);
//    memcpy(&zin[18 + 32 * 5], pub->y, 32);

    sm3_init(&ctx);
    if (strcmp(id, SM2_DEFAULT_ID) == 0) {
        sm3_update(&ctx, zin, sizeof(zin));
    } else {
        uint8_t idbits[2];
        idbits[0] = (uint8_t)(idlen >> 5);
        idbits[1] = (uint8_t)(idlen << 3);
        sm3_update(&ctx, idbits, 2);
        sm3_update(&ctx, (uint8_t *)id, idlen);
        sm3_update(&ctx, zin + 18, 32 * 6);
    }
    sm3_finish(&ctx, z);
    return 1;
}

int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen){
    if (!ctx || !key) {
        error_print();
        return -1;
    }
    ctx->key = *key;
    sm3_init(&ctx->sm3_ctx);

    if (id) {
        uint8_t z[SM3_DIGEST_SIZE];
        if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
            error_print();
            return -1;
        }
        sm2_compute_z(z, key->public_key, id, idlen);
        sm3_update(&ctx->sm3_ctx, z, sizeof(z));
    }
    return 1;
}

int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
    if (!ctx) {
        error_print();
        return -1;
    }
    if (data && datalen > 0) {
        sm3_update(&ctx->sm3_ctx, data, datalen);
    }
    return 1;
}

int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
    int ret;
    uint8_t dgst[SM3_DIGEST_SIZE];

    if (!ctx || !sig || !siglen) {
        error_print();
        return -1;
    }
    sm3_finish(&ctx->sm3_ctx, dgst);
    if ((ret = sm2_sign(&ctx->key, dgst, sig, siglen)) != 1) {
        if (ret < 0) error_print();
        return ret;
    }
    return 1;
}


int main(){

    printf("hello world");
    return 0;
}