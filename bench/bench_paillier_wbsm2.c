/*
 * @Author: Bin Li
 * @Date: 2023/11/13 22:47
 * @Description:
 */

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

//    util_banner("cp_paillier_sm2_gen:", 1);
//
    // 生成签名和验签参数
//    cp_paillier_wbsm2_gen("wbsm2_sig_params", q);

    // 从文件中读取签名

    cp_paillier_wbsm2_read("wbsm2_sig_params");

    // 性能测试
    BENCH_ONE("cp_paillier_wbsm2_sig", cp_paillier_wbsm2_sig(r, s, m, sizeof(m), 0), 1);

    // 签名
    if(cp_paillier_wbsm2_sig(r, s, m, sizeof(m), 0) != RLC_OK){
        printf("签名过程出错！\n");
        core_clean();
        return 1;
    }

    // 清除签名参数的占用的内容（该步骤可省略）
    cp_paillier_wbsm2_free();

    end:
    bn_free(r);
    bn_free(s);
    ec_free(q);

    return 0;
}
