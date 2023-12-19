/**
 * @file
 *
 * Implementation of the SM2 protocol.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_ecs_sm2_master_gen(bn_t d, ec_t q) {
    bn_t n;
    int result = RLC_OK;

    bn_null(n);

    RLC_TRY {
                        bn_new(n);
                        ec_curve_get_ord(n);
                        bn_rand_mod(d, n);
                        ec_mul_gen(q, d);
                    }
    RLC_CATCH_ANY {
            result = RLC_ERR;
        }
        RLC_FINALLY {
            bn_free(n);
        }

    return result;
}

int cp_ecs_sm2_user_gen(bn_t d, ec_t q, bn_t ms) {
    bn_t n;
    bn_t dA1, w, tA, lamb, tmpx, tmpy;
    ec_t UA, WA;
    uint8_t HA[32];
    uint8_t lamb_bin[32];
    uint8_t tmp1[256] = {0x00, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xa0};
    uint8_t tmp2[96];
    int result = RLC_OK;

    bn_null(n);
    bn_null(dA1);
    bn_null(w);
    bn_null(tA);
    bn_null(lamb);
    bn_null(tmpx);
    bn_null(tmpy);

    ec_null(UA);
    ec_null(WA);
    RLC_TRY {
                        bn_new(n);
                        bn_new(dA1);
                        bn_new(d);
                        bn_new(w);
                        bn_new(tA);
                        bn_new(lamb);
                        bn_new(tmpx);
                        bn_new(tmpy);

                        ec_new(UA);
                        ec_new(WA);

                        ec_curve_get_ord(n);

                        do {
                            // A1: 产生随机数 dA
                            bn_rand_mod(dA1, n);

                            // A2: 计算UA=[dA1]G
                            ec_mul_gen(UA, dA1);

                            // KGC1: 计算 HA=H256(ENTLA || IDA || a || b || xG || yG || xPub || yPub)
                            md_map(HA, tmp1, 256);

                            // KGC2: 产生随机数 w
                            bn_rand_mod(w, n);

                            // KGC3: 计算 WA=[w]G+UA
                            ec_mul_gen(WA, w);
                            ec_add(WA, WA, UA);

                            // kGC4: 计算 lamb = H256(xWA || yWA || HA)
                            ec_get_x(tmpx, WA);
                            ec_get_x(tmpy, WA);
                            bn_write_bin(tmp2, 32, tmpx);
                            bn_write_bin(tmp2+32, 32, tmpy);
                            memcpy(tmp2+64,HA,32);
                            md_map(lamb_bin, tmp2, 96);

                            // KGC5: 计算 tA = (w + lamb*ms)
                            bn_read_bin(lamb, lamb_bin, 32);
                            bn_mul(tA, lamb, ms);
                            bn_mod(tA, tA, n);
                            bn_add(tA, tA, w);
                            bn_mod(tA, tA, n);

                            // A3: 计算 dA = (tA + dA1)
                            bn_add(d, tA, dA1);
                            bn_mod(d, d, n);
                            ec_copy(q, WA);

                        } while (bn_is_zero(d) || bn_cmp(d, n) >= 0);
                    }
    RLC_CATCH_ANY {
            result = RLC_ERR;
        }
        RLC_FINALLY {
            bn_free(n);
        }

    return result;
}

// e = hash(m)
int cp_ecs_sm2_sig_with_hash(bn_t r, bn_t s, bn_t e, bn_t d) {
    bn_t n, k, x;
    bn_t tmp;
    ec_t p;
    int result = RLC_OK;

    bn_null(n);
    bn_null(k);
    bn_null(x);
    bn_null(tmp);
    ec_null(p);

    RLC_TRY {
                        bn_new(n);
                        bn_new(k);
                        bn_new(x);
                        bn_new(tmp);
                        ec_new(p);

                        ec_curve_get_ord(n);
                        do {
                            // 1. e = Hash(M)

                            // 2. (x1, y1) = [k]G, r = (e + x1) mod n
                            do {
                                bn_rand_mod(k, n);
                                ec_mul_gen(p, k);  // p = [k]G
                                ec_get_x(x, p);
                                bn_add(r, x, e);
                                bn_mod(r, r, n);
                            } while (bn_is_zero(r));

                            // 3. s = ((1+d)^-1 * (k-rd)) mod n
                            bn_add_dig(s, d, 1);  // s = (1+d)
                            bn_mod_inv(s, s, n);  // s = (1+d)^-1
                            bn_mul(tmp, r, d);            // tmp = rd
                            bn_mod(tmp, tmp, n);
                            bn_sub(tmp, k, tmp);  // tmp = k-rd
                            bn_mod(tmp, tmp, n);
                            bn_mul(s, s, tmp);            // s = ((1+d)^-1 * (k-rd)) mod n
                            bn_mod(s, s, n);

                        } while (bn_is_zero(s));
                    }
    RLC_CATCH_ANY {
            result = RLC_ERR;
        }
        RLC_FINALLY {
            bn_free(n);
            bn_free(k);
            bn_free(x);
            bn_free(tmp);
            ec_free(p);
        }
    return result;
}

int cp_ecs_sm2_sig(bn_t r, bn_t s, uint8_t *msg, int len, int hash, bn_t d) {
    bn_t n, k, x, e;
    bn_t tmp;
    ec_t p;
    uint8_t h[RLC_MD_LEN];
    int result = RLC_OK;

    bn_null(n);
    bn_null(k);
    bn_null(x);
    bn_null(e);
    bn_null(tmp);
    ec_null(p);

    RLC_TRY {
                        bn_new(n);
                        bn_new(k);
                        bn_new(x);
                        bn_new(e);
                        bn_new(tmp);
                        ec_new(p);

                        ec_curve_get_ord(n);
                        // 1. e = Hash(M)
                        if (!hash) {
                            md_map(h, msg, len);
                            msg = h;
                            len = RLC_MD_LEN;
                        }
                        if (8 * len > bn_bits(n)) {
                            len = RLC_CEIL(bn_bits(n), 8);
                            bn_read_bin(e, msg, len);
                            bn_rsh(e, e, 8 * len - bn_bits(n));
                        } else {
                            bn_read_bin(e, msg, len);
                        }
                        cp_ecs_sm2_sig_with_hash(r, s, e, d);
                    }
    RLC_CATCH_ANY {
            result = RLC_ERR;
        }
        RLC_FINALLY {
            bn_free(n);
            bn_free(k);
            bn_free(x);
            bn_free(e);
            bn_free(tmp);
            ec_free(p);
        }
    return result;
}

// Ppub=[ms]G是主密钥，WA是声明公钥
int cp_ecs_sm2_ver(bn_t r, bn_t s, uint8_t *msg, int len, int hash, ec_t Ppub, ec_t WA) {
    bn_t n, t, e, R, lamb, tmpx, tmpy;
    ec_t p;
    ec_t q;
    uint8_t tmp1[256] = {0x00, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xa0};
    uint8_t tmp2[96], HA[32], lamb_bin[32];
    uint8_t h[RLC_MD_LEN];
    int cmp, result = 0;

    bn_null(n);
    bn_null(t);
    bn_null(e);
    bn_null(R);
    bn_null(lamb);
    bn_null(tmpx);
    bn_null(tmpy);

    ec_null(p);

    RLC_TRY {
                        bn_new(n);
                        bn_new(e);
                        bn_new(R);
                        bn_new(t);
                        bn_new(lamb);
                        bn_new(tmpx);
                        bn_new(tmpy);

                        ec_new(p);

                        ec_curve_get_ord(n);

                        // 计算用户公钥
                        // 1. 计算 HA=H256(ENTLA || IDA || a || b || xG || yG || xPub || yPub)
                        md_map(HA, tmp1, 256);

                        // 2. 计算 lamb = H256(xWA || yWA || HA)
                        ec_get_x(tmpx, WA);
                        ec_get_x(tmpy, WA);
                        bn_write_bin(tmp2, 32, tmpx);
                        bn_write_bin(tmp2+32, 32, tmpy);
                        memcpy(tmp2+64,HA,32);
                        md_map(lamb_bin, tmp2, 96);

                        // 3. 计算 PA = WA + [lamb]Ppub
                        ec_mul(q, Ppub, lamb);
                        ec_add(q, q, WA);

                        // 标准验签
                        if (bn_sign(r) == RLC_POS && bn_sign(s) == RLC_POS &&
                            !bn_is_zero(r) && !bn_is_zero(s) && ec_on_curve(q)) {
                            // 1. 检验r,s\in[1, n-1]是否成立
                            if (bn_cmp(r, n) == RLC_LT && bn_cmp(s, n) == RLC_LT) {
//                                bn_mod_inv(k, s, n);

                                // 2. 计算e=Hash(M)
                                if (!hash) {
                                    md_map(h, msg, len);
                                    msg = h;
                                    len = RLC_MD_LEN;
                                }
                                if (8 * len > bn_bits(n)) {
                                    len = RLC_CEIL(bn_bits(n), 8);
                                    bn_read_bin(e, msg, len);
                                    bn_rsh(e, e, 8 * len - bn_bits(n));
                                } else {
                                    bn_read_bin(e, msg, len);
                                }

                                // 3. R = (e + x) mod n, (x,y) = [t]P+[s]G, t = r + s
                                bn_add(t, r, s);
                                bn_mod(t, t, n);
                                ec_mul_sim_gen(p, s, q, t);
                                ec_get_x(R, p);
                                bn_mod(R, R, n);
                                bn_add(R, R, e);  // R = (e + x)
                                bn_mod(R, R, n);

                                // 4. 比较R和r是否相等
                                cmp = dv_cmp_const(R->dp, r->dp, RLC_MIN(R->used, r->used));
                                result = (cmp == RLC_NE ? 0 : 1);

                                if (R->used != r->used) {
                                    result = 0;
                                }

                                if (ec_is_infty(p)) {
                                    result = 0;
                                }
                            }
                        }
                    }
    RLC_CATCH_ANY {
            RLC_THROW(ERR_CAUGHT);
        }
        RLC_FINALLY {
            bn_free(n);
            bn_free(e);
            bn_free(v);
            bn_free(k);
            ec_free(p);
        }
    return result;
}
