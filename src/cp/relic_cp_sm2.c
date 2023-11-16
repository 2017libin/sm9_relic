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

int cp_sm2_gen(bn_t d, ec_t q) {
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

int cp_sm2_sig(bn_t r, bn_t s, uint8_t *msg, int len, int hash, bn_t d) {
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
                        do {
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
            bn_free(e);
            bn_free(tmp);
            ec_free(p);
        }
    return result;
}

// e = hash(m)
int cp_sm2_sig_with_hash(bn_t r, bn_t s, bn_t e, bn_t d) {
    bn_t n, k, x;
    bn_t tmp;
    ec_t p;
    uint8_t h[RLC_MD_LEN];
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

int cp_sm2_ver(bn_t r, bn_t s, uint8_t *msg, int len, int hash, ec_t q) {
    bn_t n, t, e, R;
    ec_t p;
    uint8_t h[RLC_MD_LEN];
    int cmp, result = 0;

    bn_null(n);
    bn_null(t);
    bn_null(e);
    bn_null(R);
    ec_null(p);

    RLC_TRY {
                        bn_new(n);
                        bn_new(e);
                        bn_new(R);
                        bn_new(t);
                        ec_new(p);

                        ec_curve_get_ord(n);

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
