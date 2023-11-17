#include "relic/relic.h"

static void bn_debug(char *prefix, bn_t a){
    printf("%s: ", prefix);
    bn_print(a);
}

static ec_t R[256];
static bn_t T1[256], N, T2, d1_add_inv, ld, miu_t_mul;

void read_t(char *filename);
int paillier_wbsm2_sig_with_hash(bn_t r, bn_t s, bn_t e);

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
    BENCH_FEW("paillier_wbsm2_sig_with_hash with obfuscation", paillier_wbsm2_sig_with_hash(r, s, e), 1);

    bn_debug("r", r);
    bn_debug("s", s);

    bn_free(r);
    bn_free(s);
    ec_free(q);

    return 0;
}