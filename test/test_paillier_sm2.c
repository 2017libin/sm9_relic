/*
 * @Author: Bin Li
 * @Date: 2023/11/13 22:47
 * @Description:
 */

#include "test_paillier_sm2.h"
/**
 * @file
 *
 * Implementation of the SM2 protocol with paillier.
 *
 * @ingroup cp
 */

#include "relic.h"

// ret = (a^b mod c - 1) // d
void L_func(bn_t ret, bn_t a, bn_t b, bn_t c, bn_t d){
    bn_mxp(ret, a, b, c);
    bn_sub_dig(ret, ret, 1);
    bn_div(ret, ret, d);
}

// 签名参数
static ec_t R[256];
static bn_t T1[256], N, T2, d1_add_inv, ld, miu_t_mul;
// 验签公钥
static ec_t q;

// 初始化签名参数
int cp_paillier_sm2_init(bn_t d){

    bn_t n, p1, p2, g, miu, ki, ri, N2, tmp1, tmp2;
    int result = RLC_OK;

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
}

static int cp_paillier_sm2_gen_test() {
    bn_t n;
    bn_t d;

    int result = RLC_OK;

    bn_null(n);
    bn_null(d);

    RLC_TRY {
                        bn_new(n);
                        bn_new(d);

                        ec_curve_get_ord(n);
                        bn_rand_mod(d, n);
                        ec_mul_gen(q, d);
                        cp_paillier_sm2_init(d);
                    }
    RLC_CATCH_ANY {
            result = RLC_ERR;
        }
        RLC_FINALLY {
            bn_free(n);
        }

    return result;
}

int cp_paillier_sm2_sig(bn_t r, bn_t s, uint8_t *msg, int len, int hash){
    bn_t e, n, N2, tmp1, tmp2;
    ec_t kG;
    uint8_t e_bin[64];
    int result = RLC_OK;

    bn_null(n);
    bn_null(N2);
    bn_null(tmp1);
    bn_null(tmp2);
    bn_null(e);

    RLC_TRY {
                        bn_new(n);
                        bn_new(N2);
                        bn_new(tmp1);
                        bn_new(tmp2);
                        bn_new(e);

                        ep_curve_get_ord(n);
                        bn_mul(N2, N, N);

                        // e = Hash(M)
                        if (!hash) {
                            md_map(e_bin, msg, len);
                            msg = e_bin;
                            len = RLC_MD_LEN;
                        }
                        if (8 * len > bn_bits(n)) {
                            len = RLC_CEIL(bn_bits(n), 8);
                            bn_read_bin(e, msg, len);
                            bn_rsh(e, e, 8 * len - bn_bits(n));
                        } else {
                            bn_read_bin(e, msg, len);
                        }

                        // 1. 计算 [k]G = \sum_{ei=1}R_i
                        ec_set_infty(kG);
                        for (int i = 0; i < len; ++i) {
                            for (int j = 0; j < 8; ++j) {
                                if ((msg[i] >> j) & 1){
                                    ec_add(kG, kG, R[i*8+j]);
                                }
                            }
                        }

                        // 2. 计算 r = (x+e) mod n
                        ec_norm(kG, kG);
                        ec_get_x(tmp1, kG);
                        bn_add(r, tmp1 ,e);
                        bn_mod(r, r, n);

                        // 3. 计算 S1=\prod_{ei=1}T1_i mod N2
                        bn_set_dig(tmp1, 1);
                        for (int i = 0; i < len; ++i) {
                            for (int j = 0; j < 8; ++j) {
                                if ((msg[i] >> j) & 1){
                                    bn_mul(tmp1, tmp1, T1[i*8+j]);
                                    bn_mod(tmp1, tmp1, N2);
                                }
                            }
                        }

                        // 4. 计算 S2=T2^r mod N2
                        bn_mxp(tmp2, T2, r, N2);

                        // 5. 计算 S3 = S1 * S2 mod N2
                        bn_mul(tmp1, tmp1, tmp2);
                        bn_mod(tmp1, tmp1, N2);

                        // 6. 计算 s
                        // 6.1 计算 tmp1 = L(S3, ld, N2, N) * ut mod N mod n
                        L_func(tmp1, tmp1, ld, N2, N);
                        bn_mul(tmp1, tmp1, miu_t_mul);
                        bn_mod(tmp1, tmp1, N);
                        bn_mod(tmp1, tmp1, n);

                        // 6.2 计算 s = (1+d)^-1*t^-1 * tmp1 mod n
                        bn_mul(s, d1_add_inv, tmp1);
                        bn_mod(s, s, n);
                    }
    RLC_CATCH_ANY {
            result = RLC_ERR;
        }
        RLC_FINALLY {
            bn_free(n);
            bn_free(N2);
            bn_free(tmp1);
            bn_free(tmp2);
            bn_free(e);
        }
    return result;
}

int cp_sm2_sig_t(bn_t r, bn_t s, uint8_t *msg, int len, int hash, bn_t d) {
    bn_t n, k, x, e;
    bn_t tmp;
    ec_t p;
    uint8_t h[RLC_MD_LEN];
    int result = RLC_OK;

    bn_null(n);
    bn_null(k);
    bn_null(x);
    bn_null(e);
    bn_null(tmp);
    ec_null(p);

    RLC_TRY {
                        bn_new(n);
                        bn_new(k);
                        bn_new(x);
                        bn_new(e);
                        bn_new(tmp);
                        ec_new(p);

                        ec_curve_get_ord(n);
                        do {
                            // 1. e = Hash(M)
                            if (!hash) {
                                md_map(h, msg, len);
                                msg = h;
                                len = RLC_MD_LEN;
                            }
                            if (8 * len > bn_bits(n)) {
                                len = RLC_CEIL(bn_bits(n), 8);
                                bn_read_bin(e, msg, len);
                                bn_rsh(e, e, 8 * len - bn_bits(n));
                            } else {
                                bn_read_bin(e, msg, len);
                            }

                            // 2. (x1, y1) = [k]G, r = (e + x1) mod n
                            do {
                                bn_rand_mod(k, n);
                                ec_mul_gen(p, k);  // p = [k]G
                                ec_get_x(x, p);
                                bn_add(r, x, e);
                                bn_mod(r, r, n);
                            } while (bn_is_zero(r));

                            // 3. s = ((1+d)^-1 * (k-rd)) mod n
                            bn_add_dig(s, d, 1);  // s = (1+d)
                            bn_mod_inv(s, s, n);  // s = (1+d)^-1
                            bn_mul(tmp, r, d);            // tmp = rd
                            bn_mod(tmp, tmp, n);
                            bn_sub(tmp, k, tmp);  // tmp = k-rd
                            bn_mod(tmp, tmp, n);
                            bn_mul(s, s, tmp);            // s = ((1+d)^-1 * (k-rd)) mod n
                            bn_mod(s, s, n);

                        } while (bn_is_zero(s));
                    }
    RLC_CATCH_ANY {
            result = RLC_ERR;
        }
        RLC_FINALLY {
            bn_free(n);
            bn_free(k);
            bn_free(x);
            bn_free(e);
            bn_free(tmp);
            ec_free(p);
        }
    return result;
}

int cp_paillier_sm2_ver(bn_t r, bn_t s, uint8_t *msg, int len, int hash, ec_t q) {
    bn_t n, t, e, R;
    ec_t p;
    uint8_t h[RLC_MD_LEN];
    int cmp, result = 0;

    bn_null(n);
    bn_null(t);
    bn_null(e);
    bn_null(R);
    ec_null(p);

    RLC_TRY {
                        bn_new(n);
                        bn_new(e);
                        bn_new(R);
                        bn_new(t);
                        ec_new(p);

                        ec_curve_get_ord(n);

                        if (bn_sign(r) == RLC_POS && bn_sign(s) == RLC_POS &&
                            !bn_is_zero(r) && !bn_is_zero(s) && ec_on_curve(q)) {
                            // 1. 检验r,s\in[1, n-1]是否成立
                            if (bn_cmp(r, n) == RLC_LT && bn_cmp(s, n) == RLC_LT) {
//                                bn_mod_inv(k, s, n);

                                // 2. 计算e=Hash(M)
                                if (!hash) {
                                    md_map(h, msg, len);
                                    msg = h;
                                    len = RLC_MD_LEN;
                                }
                                if (8 * len > bn_bits(n)) {
                                    len = RLC_CEIL(bn_bits(n), 8);
                                    bn_read_bin(e, msg, len);
                                    bn_rsh(e, e, 8 * len - bn_bits(n));
                                } else {
                                    bn_read_bin(e, msg, len);
                                }
                                // 3. R = (e + x) mod n, (x,y) = [t]P+[s]G, t = r + s
                                bn_add(t, r, s);
                                bn_mod(t, t, n);
                                ec_mul_sim_gen(p, s, q, t);
                                ec_get_x(R, p);
                                bn_mod(R, R, n);
                                bn_add(R, R, e);  // R = (e + x)
                                bn_mod(R, R, n);

                                // 4. 比较R和r是否相等
                                cmp = dv_cmp_const(R->dp, r->dp, RLC_MIN(R->used, r->used));
                                result = (cmp == RLC_NE ? 0 : 1);

                                if (R->used != r->used) {
                                    result = 0;
                                }

                                if (ec_is_infty(p)) {
                                    result = 0;
                                }
                            }
                        }
                    }
    RLC_CATCH_ANY {
            RLC_THROW(ERR_CAUGHT);
        }
        RLC_FINALLY {
            bn_free(n);
            bn_free(e);
            bn_free(v);
            bn_free(k);
            ec_free(p);
        }
    return result;
}

void cp_paillier_sm2_write(char *filename){
    FILE *fd = fopen(filename, "wb");
    if (fd == NULL){
        perror("open file failed!");
        exit(1);
    }
//    printf("per %d bytes , total %d bytes", sizeof(ec_t), sizeof(R));

    // 写入参数
    fwrite(R, sizeof(R), 1, fd);
    fwrite(T1, sizeof(T1), 1, fd);
    fwrite(N, sizeof(bn_t), 1, fd);
    fwrite(T2, sizeof(bn_t), 1, fd);
    fwrite(d1_add_inv, sizeof(bn_t), 1, fd);
    fwrite(ld, sizeof(bn_t), 1, fd);
    fwrite(miu_t_mul, sizeof(bn_t), 1, fd);
    fwrite(q, sizeof(ec_t), 1, fd);

    // 关闭文件
    fclose(fd);
}


void cp_paillier_sm2_read(char *filename){
    FILE *fd = fopen(filename, "rb");
    if (fd == NULL){
        perror("open file failed!");
        exit(1);
    }
//    printf("per %d bytes , total %d bytes", sizeof(ec_t), sizeof(R));

    // 写入参数
    fread(R, sizeof(R), 1, fd);
    fread(T1, sizeof(T1), 1, fd);
    fread(N, sizeof(bn_t), 1, fd);
    fread(T2, sizeof(bn_t), 1, fd);
    fread(d1_add_inv, sizeof(bn_t), 1, fd);
    fread(ld, sizeof(bn_t), 1, fd);
    fread(miu_t_mul, sizeof(bn_t), 1, fd);
    fread(q, sizeof(ec_t), 1, fd);

    // 关闭文件
    fclose(fd);
}

int main(void) {
    // 为参数分配空间
    if (core_init() != RLC_OK) {
        printf("参数init失败！\n");
        core_clean();
        return 1;
    }

    // 为参数设置具体的值
    if(ec_param_set_any() != RLC_OK){
        printf("参数set失败！\n");
        core_clean();
        return 1;
    }

    int code = RLC_ERR;
    bn_t d, r, s;

    uint8_t m[5] = { 1, 2, 3, 4, 0 }, h[RLC_MD_LEN];
    uint8_t m_test[1] = {0x11};

    bn_null(d);
    bn_null(r);
    bn_null(s);
    bn_new(d);
    bn_new(r);
    bn_new(s);

    util_banner("cp_paillier_sm2_gen:", 1);
    // 生成公私钥
//    cp_paillier_sm2_gen_test();
//     将签名和验签参数写入文件中
//    cp_paillier_sm2_write("params");

    // 从文件中读取签名和验签参数
    cp_paillier_sm2_read("params");
    util_banner("cp_paillier_sm2_sig:", 1);

    // 签名
    if(cp_paillier_sm2_sig(r, s, m, sizeof(m), 0) != RLC_OK){
        printf("签名过程出错！\n");
        core_clean();
        return 1;
    }
    bn_debug("r", r);
    bn_debug("s", s);

    util_banner("cp_paillier_sm2_ver:", 1);
    if(cp_paillier_sm2_ver(r, s, m, sizeof(m), 0, q) == 1){
        printf("verify success!\n");
    }else{
        printf("verify failed！\n");
    }

    end:
    bn_free(d);
    bn_free(r);
    bn_free(s);
    ec_free(q);

    return 0;
}
