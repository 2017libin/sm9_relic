#include <stdio.h>
#include "relic.h"

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
    bn_t e, d, r, s;
    ec_t q;
    uint8_t m[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];

    bn_null(e);
    bn_null(d);
    bn_null(r);
    bn_null(s);
    ec_null(q);

    bn_new(e);
    bn_new(d);
    bn_new(r);
    bn_new(s);
    ec_new(q);

    // 生成公私钥
    cp_sm2_gen(d, q);

    // 性能测试
    util_banner("sm2 sig performance test:", 1);
    bn_rand(e, RLC_POS, 256);
    BENCH_ONE("cp_sm2_sig_with_hash", cp_sm2_sig_with_hash(r, s, e, e), 1);
    BENCH_ONE("cp_sm2_sig", cp_sm2_sig(r, s, m, sizeof(m), 0, d), 1);

    end:
    bn_free(d);
    bn_free(r);
    bn_free(s);
    ec_free(q);
    return 0;
}
