#include "relic.h"
#include "sm9.h"

void test_sm9_pairing(){
    ep_t g1;
    ep2_t Ppub;
    fp12_t r;

    ep_null(g1);
    ep_new(g1);
    ep2_null(Ppub);
    ep2_new(Ppub);

    char g1x[] = "93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD";
    char g1y[] = "21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616";
    char g1z[] = "1";

    fp_read_str(g1->x, g1x, strlen(g1x), 16);
    fp_read_str(g1->y, g1y, strlen(g1y), 16);
    fp_read_str(g1->z, g1z, strlen(g1z), 16);


    char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
    char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
    char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
    char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
    char z0[] = "1";
    char z1[] = "0";

    fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
    fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
    fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
    fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
    fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
    fp_read_str(Ppub->z[1], z1, strlen(z1), 16);

    fp12_null(r);
    fp12_new(r);

    sm9_init();

#if 1
    // 测试正确性
    sm9_pairing_fastest(r, Ppub, g1);
    printf("in: Ppub\n");
    ep2_print(Ppub);
    printf("in: g1\n");
    ep_print(g1);
    printf("out: r\n");
    fp12_print(r);
#endif

    sm9_clean();
    g1_free(g1);
    ep2_free(Ppub);
    fp12_free(r);
}

int main(int argc, char *argv[]) {
    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }

    if (pc_param_set_any() != RLC_OK) {
        RLC_THROW(ERR_NO_CURVE);
        core_clean();
        return 0;
    }

    test_sm9_pairing();

    core_clean();

    return 0;
}
