/*
 * @Author: Bin Li
 * @Date: 2023/10/16 16:33
 * @Description:
 */
#include "relic.h"

void a(){
    RLC_THROW(ERR_CAUGHT);
}

int main(){
    // 需要先初始化环境变量core_ctx
    if (core_init() != RLC_OK) {
        return RLC_ERR; // RELIC 初始化失败
    }

    RLC_TRY {
        // 可能引发异常的代码，如密码学运算或数学操作
        a();
    } RLC_CATCH_ANY {
        // 处理异常的代码
        printf("error!");
    } RLC_FINALLY {
        // 最终处理，如资源释放
        printf("finally!\n");
    }
    return 0;
}