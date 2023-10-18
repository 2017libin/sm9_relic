#include <stdio.h>
#include "relic.h"

static int ecdsa(void) {
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
    ec_t q;
    uint8_t m[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];

    bn_null(d);
    bn_null(r);
    bn_null(s);
    ec_null(q);

    bn_new(d);
    bn_new(r);
    bn_new(s);
    ec_new(q);

    // 生成公私钥
    cp_ecdsa_gen(d, q);

    // 签名
    if(cp_ecdsa_sig(r, s, m, sizeof(m), 0, d) != RLC_OK){
        printf("签名过程出错！\n");
        core_clean();
        return 1;
    }
    if(cp_ecdsa_ver(r, s, m, sizeof(m), 0, q) == 1){
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

int main() {
    ecdsa();
    // hello();
    return 0;
}
