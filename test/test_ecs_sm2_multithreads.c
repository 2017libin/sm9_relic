#include <stdio.h>
#include "relic.h"
#include <omp.h>

static int ecs_sm2_gen_test(int thread_num) {

    int code = RLC_ERR;
    bn_t ms, d, r, s;
    ec_t Ppub, WA;
    uint8_t m[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];
    bn_null(ms);
    bn_null(d);
    bn_null(r);
    bn_null(s);
    ec_null(Ppub);
    ec_null(WA);

    bn_new(ms);
    bn_new(d);
    bn_new(r);
    bn_new(s);
    ec_new(Ppub);
    ec_new(WA);

#if 1
    // 多线程测试
    double begin,end;
    size_t count = 10000;

    // 签名性能测试
    begin = omp_get_wtime();
    // 生成公私钥
    cp_ecs_sm2_master_gen(ms, Ppub);

#pragma omp parallel for num_threads(thread_num)
    for(int i = 0; i < count;i++){
        cp_ecs_sm2_user_gen(d, WA, ms);
    }
    end = omp_get_wtime();
    printf("gen - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
#endif
           

    end:
    bn_free(d);
    bn_free(r);
    bn_free(s);
    ec_free(q);
    return 0;
}

static int ecs_sm2_sign_test(int thread_num) {
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
    cp_sm2_gen(d, q);

    // 签名

#if 1
    // 多线程测试
    double begin,end;
    size_t count = 10000;

    // 签名性能测试
    begin = omp_get_wtime();
#pragma omp parallel for num_threads(thread_num)
    for(int i = 0; i < count;i++){
        cp_sm2_sig(r, s, m, sizeof(m), 0, d);
    }
    end = omp_get_wtime();
    printf("sign - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
#endif


    end:
    bn_free(d);
    bn_free(r);
    bn_free(s);
    ec_free(q);
    return 0;
}
static int ecs_sm2_very_test(int thread_num) {

    int code = RLC_ERR;
    bn_t ms, d, r, s;
    ec_t Ppub, WA;
    uint8_t m[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];
    bn_null(ms);
    bn_null(d);
    bn_null(r);
    bn_null(s);
    ec_null(Ppub);
    ec_null(WA);

    bn_new(ms);
    bn_new(d);
    bn_new(r);
    bn_new(s);
    ec_new(Ppub);
    ec_new(WA);

    // 生成公私钥
    cp_ecs_sm2_master_gen(ms, Ppub);
    cp_ecs_sm2_user_gen(d, WA, ms);
    cp_ecs_sm2_sig(r, s, m, sizeof(m), 0, d);
#if 1
    // 多线程测试
    double begin,end;
    size_t count = 10000;

    // 签名性能测试
    begin = omp_get_wtime();
#pragma omp parallel for num_threads(thread_num)
    for(int i = 0; i < count;i++){
        cp_ecs_sm2_ver(r, s, m, sizeof(m), 0, Ppub, WA);
    }
    end = omp_get_wtime();
    printf("very - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
#endif

    end:
    bn_free(d);
    bn_free(r);
    bn_free(s);
    ec_free(q);
    return 0;
}
int main() {
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

//    ecs_sm2_gen_test(1);
//    ecs_sm2_gen_test(2);
//    ecs_sm2_gen_test(4);
//    ecs_sm2_gen_test(8);
//    ecs_sm2_gen_test(12);
//    ecs_sm2_gen_test(16);
    ecs_sm2_sign_test(1);
    ecs_sm2_sign_test(2);
    ecs_sm2_sign_test(4);
    ecs_sm2_sign_test(8);
    ecs_sm2_sign_test(12);
    ecs_sm2_sign_test(16);
    ecs_sm2_very_test(1);
    ecs_sm2_very_test(2);
    ecs_sm2_very_test(4);
    ecs_sm2_very_test(8);
    ecs_sm2_very_test(12);
    ecs_sm2_very_test(16);
    return 0;
}
