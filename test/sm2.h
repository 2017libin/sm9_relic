/*
 * @Author: Bin Li
 * @Date: 2023/8/15 01:49
 * @Description:
 */

#ifndef RELIC_SM2_H
#define RELIC_SM2_H

#include "relic.h"
#include "gmssl/sm3.h"

#define SM2_DEFAULT_ID		"1234567812345678"
#define SM2_DEFAULT_ID_LENGTH	(sizeof(SM2_DEFAULT_ID) - 1)  // LENGTH for string and SIZE for bytes
#define SM2_MAX_ID_BITS		65535
#define SM2_MAX_ID_LENGTH	(SM2_MAX_ID_BITS/8)

typedef struct {
    ep_t public_key;
    uint8_t private_key[32];
} SM2_KEY;

typedef struct {
    SM3_CTX sm3_ctx;
    SM2_KEY key;
} SM2_SIGN_CTX;

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
} SM2_SIGNATURE;

// sm2签名接口
int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen);
int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen);

#endif //RELIC_SM2_H
