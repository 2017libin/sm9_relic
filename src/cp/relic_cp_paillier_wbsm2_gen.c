/*
 * @Author: Bin Li
 * @Date: 2023/11/13 22:47
 * @Description:
 */

/**
 * @file
 *
 * Implementation of the SM2 protocol with paillier.
 *
 * @ingroup cp
 */

#include "relic.h"

// ret = (a^b mod c - 1) // d
static void L_func(bn_t ret, bn_t a, bn_t b, bn_t c, bn_t d){
    bn_mxp(ret, a, b, c);
    bn_sub_dig(ret, ret, 1);
    bn_div(ret, ret, d);
}

// 签名参数
static ec_t R[256];
static bn_t T1[256], N, T2, d1_add_inv, ld, miu_t_mul;

void cp_paillier_wbsm2_write(char *filename){
    FILE *fd = fopen(filename, "wb");
    if (fd == NULL){
        perror("open file failed!");
        exit(1);
    }

    // 写入签名参数
    fwrite(R, sizeof(R), 1, fd);
    fwrite(T1, sizeof(T1), 1, fd);
    fwrite(N, sizeof(bn_t), 1, fd);
    fwrite(T2, sizeof(bn_t), 1, fd);
    fwrite(d1_add_inv, sizeof(bn_t), 1, fd);
    fwrite(ld, sizeof(bn_t), 1, fd);
    fwrite(miu_t_mul, sizeof(bn_t), 1, fd);

    // 关闭文件
    fclose(fd);
}

// 初始化签名参数
int cp_paillier_wbsm2_init(bn_t d){

    bn_t n, p1, p2, g, miu, ki, ri, N2, tmp1, tmp2;
    int result = RLC_OK;

    bn_null(n);
    bn_null(p1);
    bn_null(p2);
    bn_null(g);
    bn_null(miu);
    bn_null(ki);
    bn_null(ri);
    bn_null(N2);
    bn_null(tmp1);
    bn_null(tmp2);

    bn_new(n);
    bn_new(p1);
    bn_new(p2);
    bn_new(g);
    bn_new(miu);
    bn_new(ki);
    bn_new(ri);
    bn_new(N2);
    bn_new(tmp1);
    bn_new(tmp2);

    ec_curve_get_ord(n);

    // 1. 生成随机素数p1, p2
    do {
        bn_gen_prime(p1, 512);
        bn_gen_prime(p2, 512);
    } while (bn_is_even(p1) || bn_is_even(p2));

    // 2. 计算N=p1*p2, g=N+1, ld=lcm(p1-1,p2-1)
    bn_mul(N, p1, p2);
    bn_add_dig(g, N, 1);
    bn_sub_dig(tmp1, p1, 1);
    bn_sub_dig(tmp2, p2, 1);
    bn_lcm(ld, tmp1, tmp2);

    // 3. miu = L(g, ld, N^2, N)^-1 mod N
    bn_mul(N2, N, N);
    L_func(miu, g, ld, N2, N);

    bn_mod_inv(miu, miu, N);

    // 4. 随机生成ki, ri, 并计算T1_i, R_i
    for (int i = 0; i < 256; ++i) {

        bn_rand_mod(tmp1, n);  // tmp1 = ki
        bn_rand_mod(tmp2, n);  // tmp2 = ri
        // T1[i] = g^ki * ri^N mod N2
        bn_mxp(T1[i], g, tmp1, N2);
        bn_mxp(tmp2, tmp2, N, N2);
        bn_mul(T1[i], T1[i], tmp2);
        bn_mod(T1[i], T1[i], N2);
        // R[i] = [ki]G
        ec_mul_gen(R[i], tmp1);
    }

    // 5. 生成随机r，计算T2 = g^-d * r^N mod N2
    bn_rand_mod(tmp1, n);  // r
    bn_sub(tmp2, n, d);  // tmp2 = -d mod n
    bn_mxp(T2, g, tmp2, N2);  // g^-d mod N2
    bn_mxp(tmp1, tmp1, N, N2);  // r^N mod N2
    bn_mul(T2, T2, tmp1);
    bn_mod(T2, T2, N2);

    // 生成随机t，计算和保存d1_add_inv = (1+d)^-1 * t^-1, miu*t
    bn_rand_mod(tmp1, n);  // t
    bn_add_dig(d1_add_inv, d, 1);
    bn_mul(d1_add_inv, d1_add_inv, tmp1);
    bn_mod_inv(d1_add_inv, d1_add_inv, n);
    bn_mul(miu_t_mul, miu, tmp1);
    bn_mod(miu_t_mul, miu_t_mul, N);

    bn_free(n);
    bn_free(p1);
    bn_free(p2);
    bn_free(g);
    bn_free(miu);
    bn_free(ki);
    bn_free(ri);
    bn_free(N2);
    bn_free(tmp1);
    bn_free(tmp2);
}

int cp_paillier_wbsm2_gen(char *filename, ec_t q) {
    bn_t n;
    bn_t d;

    int result = RLC_OK;

    bn_null(n);
    bn_null(d);

    for (int i = 0; i < 256; ++i) {
        ec_null(R[i]);
        bn_null(T1[i]);
    }
    bn_null(N);
    bn_null(T2);
    bn_null(d1_add_inv);
    bn_null(ld);
    bn_null(miu_t_mul);

    RLC_TRY {
            for (int i = 0; i < 256; ++i) {
                ec_new(R[i]);
                bn_new(T1[i]);
            }
            bn_new(N);
            bn_new(T2);
            bn_new(d1_add_inv);
            bn_new(ld);
            bn_new(miu_t_mul);

            bn_new(n);
            bn_new(d);
            ec_curve_get_ord(n);
            bn_rand_mod(d, n);
            ec_mul_gen(q, d);
            cp_paillier_wbsm2_init(d);
            cp_paillier_wbsm2_write(filename);
    }
    RLC_CATCH_ANY {
            result = RLC_ERR;
    }
    RLC_FINALLY {
            bn_free(n);
            bn_free(d);
            for (int i = 0; i < 256; ++i) {
                ec_free(R[i]);
                bn_free(T1[i]);
            }
            bn_free(N);
            bn_free(T2);
            bn_free(d1_add_inv);
            bn_free(ld);
            bn_free(miu_t_mul);
    }

    return result;
}