# 安装relic
1. mkdir build && cd build && cmake .. && make install -j8
# tigress 混淆代码步骤
1. 产生混淆代码paillier_wbsm2_obs.c：`bash tigress_paillier_wbsm2.sh`
2. 删除混淆代码中的main函数
3. 使用main.c对调用混淆代码中的签名函数
4. 将main.c和paillier_wbsm2_obs.c一起编译成可执行文件：`gcc -o obs main.c paillier_wbsm2_obs.c -lrelic_s`
   1. 动态链接执行会出错，暂未解决
5. 执行程序：`./obs`
```c
//
// main.c
//
#include "relic/relic.h"

static void bn_debug(char *prefix , bn_st *a ) {
    {
        printf((char const */* __restrict  */) "%s: ", prefix);
        bn_print((bn_st */* const  */) a);
        return;
    }
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
```