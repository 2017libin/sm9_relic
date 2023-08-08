#include "relic.h"

int main(int argc, char *argv[]) {
    if (core_init() != RLC_OK) {
        core_clean();
        printf("初始化失败！\n");
        return 1;
    }
    printf("初始化成功！\n");

    if (pc_param_set_any() != RLC_OK) {
        RLC_THROW(ERR_NO_CURVE);
        core_clean();
        return 0;
    }

    return 0;
}
