#include "relic/relic.h"

static void bn_debug(char *prefix, bn_t a){
    printf("%s: ", prefix);
    bn_print(a);
}

static ec_t R[256];
static bn_t T1[256], N, T2, d1_add_inv, ld, miu_t_mul;

void read_t(char *filename){
    FILE *fd = fopen(filename, "rb");
    if (fd == NULL){
        perror("open file failed!");
        exit(1);
    }

    for (int i = 0; i < 256; ++i) {
        ec_null(R[i]);
        bn_null(T1[i]);
    }

    bn_null(N);
    bn_null(T2);
    bn_null(d1_add_inv);
    bn_null(ld);
    bn_null(miu_t_mul);

    for (int i = 0; i < 256; ++i) {
        ec_new(R[i]);
        bn_new(T1[i]);
    }

    bn_new(N);
    bn_new(T2);
    bn_new(d1_add_inv);
    bn_new(ld);
    bn_new(miu_t_mul);

    fread(R, sizeof(R), 1, fd);
    fread(T1, sizeof(T1), 1, fd);
    fread(N, sizeof(bn_t), 1, fd);
    fread(T2, sizeof(bn_t), 1, fd);
    fread(d1_add_inv, sizeof(bn_t), 1, fd);
    fread(ld, sizeof(bn_t), 1, fd);
    fread(miu_t_mul, sizeof(bn_t), 1, fd);

    fclose(fd);
}

static void L_func(bn_t ret, bn_t a, bn_t b, bn_t c, bn_t d){
    bn_mxp(ret, a, b, c);
    bn_sub_dig(ret, ret, 1);
    bn_div(ret, ret, d);
}

int paillier_wbsm2_sig_with_hash(bn_t r, bn_t s, bn_t e){
    bn_t n, N2, tmp1, tmp2;
    ec_t kG;
    int result = RLC_OK;
    uint8_t msg[32];

    bn_null(n);
    bn_null(N2);
    bn_null(tmp1);
    bn_null(tmp2);

    RLC_TRY {
                        bn_new(n);
                        bn_new(N2);
                        bn_new(tmp1);
                        bn_new(tmp2);

                        ep_curve_get_ord(n);
                        bn_mul(N2, N, N);

                        // e = Hash(M)
                        bn_write_bin(msg, 32, e);

                        // 1. 计算 [k]G = \sum_{ei=1}R_i
                        ec_set_infty(kG);
                        for (int i = 0; i < 32; ++i) {
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
                        for (int i = 0; i < 32; ++i) {
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

void print_hex(char * prefix, uint8_t * bytes, size_t len){
    printf("%s: ", prefix);
    for (int i = 0; i < len; ++i) {
        printf("%02X ", bytes[i]);
    }
    printf("\n");
}

int main(void) {
    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }

    if(ec_param_set_any() != RLC_OK){
        core_clean();
        return 1;
    }

    int code = RLC_ERR;
    bn_t r, s, e;
    ec_t q;

    uint8_t m[5] = { 1, 2, 3, 4, 0 }, h[RLC_MD_LEN];
    uint8_t m_test[1] = {0x11};

    bn_null(r);
    bn_null(s);
    bn_null(e);
    ec_null(q);

    bn_new(r);
    bn_new(s);
    bn_new(e);
    ec_new(q);

    // 生成签名和验签参数
//    cp_paillier_wbsm2_gen("wbsm2_sig_params", q);

    read_t ("wbsm2_sig_params");

    // 性能测试
    util_banner("paillier wbsm2 sig performance test:", 1);
    bn_rand(e, RLC_POS, 256);
    BENCH_FEW("paillier_wbsm2_sig_with_hash", paillier_wbsm2_sig_with_hash(r, s, e), 1);

    bn_debug("r", r);
    bn_debug("s", s);

    bn_free(r);
    bn_free(s);
    ec_free(q);

    return 0;
}