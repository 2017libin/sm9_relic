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

int sig_t(bn_t r, bn_t s, uint8_t *msg, int len, int hash){
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

                        ec_set_infty(kG);
                        for (int i = 0; i < len; ++i) {
                            for (int j = 0; j < 8; ++j) {
                                if ((msg[i] >> j) & 1){
                                    ec_add(kG, kG, R[i*8+j]);
                                }
                            }
                        }

                        ec_norm(kG, kG);
                        ec_get_x(tmp1, kG);
                        bn_add(r, tmp1 ,e);
                        bn_mod(r, r, n);

                        bn_set_dig(tmp1, 1);
                        for (int i = 0; i < len; ++i) {
                            for (int j = 0; j < 8; ++j) {
                                if ((msg[i] >> j) & 1){
                                    bn_mul(tmp1, tmp1, T1[i*8+j]);
                                    bn_mod(tmp1, tmp1, N2);
                                }
                            }
                        }

                        bn_mxp(tmp2, T2, r, N2);

                        bn_mul(tmp1, tmp1, tmp2);
                        bn_mod(tmp1, tmp1, N2);

                        L_func(tmp1, tmp1, ld, N2, N);
                        bn_mul(tmp1, tmp1, miu_t_mul);
                        bn_mod(tmp1, tmp1, N);
                        bn_mod(tmp1, tmp1, n);

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
    bn_t r, s;
    ec_t q;

    uint8_t m[5] = { 1, 2, 3, 4, 0 }, h[RLC_MD_LEN];
    uint8_t m_test[1] = {0x11};

    bn_null(r);
    bn_null(s);
    ec_null(q);
    bn_new(r);
    bn_new(s);
    ec_new(q);
    // 生成签名和验签参数
//    cp_paillier_wbsm2_gen("wbsm2_sig_params", q);

    read_t ("wbsm2_sig_params");

    util_banner("cp_paillier_sm2_sig:", 1);

    if(sig_t (r, s, m, sizeof(m), 0) != RLC_OK){
        core_clean();
        return 1;
    }
    bn_debug("r", r);
    bn_debug("s", s);

    bn_free(r);
    bn_free(s);
    ec_free(q);

    return 0;
}