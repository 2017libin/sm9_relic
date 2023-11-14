/*
 * @Author: Bin Li
 * @Date: 2023/11/13 22:47
 * @Description:
 */

#ifndef RELIC_TEST_PAILLIER_SM2_H
#define RELIC_TEST_PAILLIER_SM2_H

#include <stdlib.h>
#include <stdio.h>

#include "relic.h"

static void bn_debug(char *prefix, bn_t a){
    printf("%s: ", prefix);
    bn_print(a);
}
#endif //RELIC_TEST_PAILLIER_SM2_H
