/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "py/objstr.h"
#include "py/objint.h"
#include "py/mpz.h"

#include "monero/monero.h"
#define RSIG_SIZE 6176

typedef struct _mp_obj_hasher_t {
  mp_obj_base_t base;
  Hasher h;
} mp_obj_hasher_t;

typedef struct _mp_obj_ge25519_t {
    mp_obj_base_t base;
    ge25519 p;
} mp_obj_ge25519_t;

typedef struct _mp_obj_bignum256modm_t {
    mp_obj_base_t base;
    bignum256modm p;
} mp_obj_bignum256modm_t;

typedef union {
  xmr_range_sig_t r;
  unsigned char d[RSIG_SIZE];
} rsig_union;


//
// Helpers
//

STATIC const mp_obj_type_t mod_trezorcrypto_monero_ge25519_type;
STATIC const mp_obj_type_t mod_trezorcrypto_monero_bignum256modm_type;
STATIC const mp_obj_type_t mod_trezorcrypto_monero_hasher_type;


static uint64_t mp_obj_uint64_get_checked(mp_const_obj_t self_in) {
#if MICROPY_LONGINT_IMPL != MICROPY_LONGINT_IMPL_MPZ
#  error "MPZ supported only"
#endif

    if (MP_OBJ_IS_SMALL_INT(self_in)) {
        return MP_OBJ_SMALL_INT_VALUE(self_in);
    } else {
        byte buff[8];
        uint64_t res = 0;
        mp_obj_t * o = MP_OBJ_TO_PTR(self_in);

        mp_obj_int_to_bytes_impl(o, true, 8, buff);
        for (int i = 0; i<8; i++){
            res <<= i > 0 ? 8 : 0;
            res |= (uint64_t)(buff[i] & 0xff);
        }
        return res;
    }
}

static uint64_t mp_obj_get_uint64(mp_const_obj_t arg) {
    if (arg == mp_const_false) {
        return 0;
    } else if (arg == mp_const_true) {
        return 1;
    } else if (MP_OBJ_IS_SMALL_INT(arg)) {
        return MP_OBJ_SMALL_INT_VALUE(arg);
    } else if (MP_OBJ_IS_TYPE(arg, &mp_type_int)) {
        return mp_obj_uint64_get_checked(arg);
    } else {
        if (MICROPY_ERROR_REPORTING == MICROPY_ERROR_REPORTING_TERSE) {
            mp_raise_TypeError("can't convert to int");
        } else {
            nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError,
                                                    "can't convert %s to int", mp_obj_get_type_str(arg)));
        }
    }
}

STATIC mp_obj_t mp_obj_new_scalar(){
  mp_obj_bignum256modm_t *o = m_new_obj(mp_obj_bignum256modm_t);
  o->base.type = &mod_trezorcrypto_monero_bignum256modm_type;
  set256_modm(o->p, 0);
  return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mp_obj_new_ge25519(){
  mp_obj_ge25519_t *o = m_new_obj(mp_obj_ge25519_t);
  o->base.type = &mod_trezorcrypto_monero_ge25519_type;
  ge25519_set_neutral(&o->p);
  return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mp_obj_from_scalar(const bignum256modm in){
    mp_obj_bignum256modm_t *o = m_new_obj(mp_obj_bignum256modm_t);
    o->base.type = &mod_trezorcrypto_monero_bignum256modm_type;
    memcpy(&o->p, in, sizeof(bignum256modm));
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mp_obj_from_ge25519(const ge25519 * in){
    mp_obj_ge25519_t *o = m_new_obj(mp_obj_ge25519_t);
    o->base.type = &mod_trezorcrypto_monero_ge25519_type;
    memcpy(&o->p, in, sizeof(ge25519));
    return MP_OBJ_FROM_PTR(o);
}

STATIC void mp_unpack_ge25519(ge25519 * r, const mp_obj_t arg){
    mp_buffer_info_t buff;
    mp_get_buffer_raise(arg, &buff, MP_BUFFER_READ);
    if (buff.len != 32) {
        mp_raise_ValueError("Invalid length of the EC point");
    }

    const int res = ge25519_unpack_vartime(r, buff.buf);
    if (res != 1){
        mp_raise_ValueError("Point decoding error");
    }
}

STATIC void mp_unpack_scalar(bignum256modm r, const mp_obj_t arg){
    mp_buffer_info_t buff;
    mp_get_buffer_raise(arg, &buff, MP_BUFFER_READ);
    if (buff.len < 32 || buff.len > 64) {
        mp_raise_ValueError("Invalid length of secret key");
    }
    expand256_modm(r, buff.buf, buff.len);
}

#define MP_OBJ_IS_GE25519(o) MP_OBJ_IS_TYPE((o), &mod_trezorcrypto_monero_ge25519_type)
#define MP_OBJ_IS_SCALAR(o) MP_OBJ_IS_TYPE((o), &mod_trezorcrypto_monero_bignum256modm_type)
#define MP_OBJ_PTR_MPC_GE25519(o) ((const mp_obj_ge25519_t*) (o))
#define MP_OBJ_PTR_MPC_SCALAR(o) ((const mp_obj_bignum256modm_t*) (o))
#define MP_OBJ_PTR_MP_GE25519(o) ((mp_obj_ge25519_t*) (o))
#define MP_OBJ_PTR_MP_SCALAR(o) ((mp_obj_bignum256modm_t*) (o))
#define MP_OBJ_C_GE25519(o) (MP_OBJ_PTR_MPC_GE25519(o)->p)
#define MP_OBJ_GE25519(o) (MP_OBJ_PTR_MP_GE25519(o)->p)
#define MP_OBJ_C_SCALAR(o) (MP_OBJ_PTR_MPC_SCALAR(o)->p)
#define MP_OBJ_SCALAR(o) (MP_OBJ_PTR_MP_SCALAR(o)->p)

STATIC inline void assert_ge25519(const mp_obj_t o){
    if (!MP_OBJ_IS_GE25519(o)){
        mp_raise_ValueError("ge25519 expected");
    }
}

STATIC inline void assert_scalar(const mp_obj_t o){
    if (!MP_OBJ_IS_SCALAR(o)){
        mp_raise_ValueError("scalar expected");
    }
}

//
// Constructors
//


STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_ge25519_t *o = m_new_obj(mp_obj_ge25519_t);
    o->base.type = type;

    if (n_args == 0) {
        ge25519_set_neutral(&o->p);
    } else if (n_args == 1 && MP_OBJ_IS_GE25519(args[0])) {
        ge25519_copy(&o->p, &MP_OBJ_C_GE25519(args[0]));
    } else if (n_args == 1 && MP_OBJ_IS_STR_OR_BYTES(args[0])) {
        mp_unpack_ge25519(&o->p, args[0]);
    } else {
        mp_raise_ValueError("Invalid ge25519 constructor");
    }

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mod_trezorcrypto_monero_ge25519___del__(mp_obj_t self) {
    mp_obj_ge25519_t *o = MP_OBJ_TO_PTR(self);
    memzero(&(o->p), sizeof(ge25519));
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_ge25519___del___obj, mod_trezorcrypto_monero_ge25519___del__);

STATIC mp_obj_t mod_trezorcrypto_monero_bignum256modm_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_bignum256modm_t *o = m_new_obj(mp_obj_bignum256modm_t);
    o->base.type = type;

    if (n_args == 0) {
        set256_modm(o->p, 0);
    } else if (n_args == 1 && MP_OBJ_IS_SCALAR(args[0])) {
        copy256_modm(o->p, MP_OBJ_C_SCALAR(args[0]));
    } else if (n_args == 1 && MP_OBJ_IS_STR_OR_BYTES(args[0])) {
        mp_unpack_scalar(o->p, args[0]);
    } else if (n_args == 1 && mp_obj_is_integer(args[0])) {
        uint64_t v = mp_obj_get_uint64(args[0]);
        set256_modm(o->p, v);
    } else {
        mp_raise_ValueError("Invalid scalar constructor");
    }

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mod_trezorcrypto_monero_bignum256modm___del__(mp_obj_t self) {
    mp_obj_bignum256modm_t *o = MP_OBJ_TO_PTR(self);
    memzero(o->p, sizeof(bignum256modm));
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_bignum256modm___del___obj, mod_trezorcrypto_monero_bignum256modm___del__);


STATIC mp_obj_t mod_trezorcrypto_monero_hasher_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
  mp_arg_check_num(n_args, n_kw, 0, 1, false);
  mp_obj_hasher_t *o = m_new_obj(mp_obj_hasher_t);
  o->base.type = type;
  xmr_hasher_init(&(o->h));

  if (n_args == 1 && MP_OBJ_IS_STR_OR_BYTES(args[0])) {
    mp_buffer_info_t buff;
    mp_get_buffer_raise(args[0], &buff, MP_BUFFER_READ);
    xmr_hasher_update(&o->h, buff.buf, buff.len);
  }

  return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mod_trezorcrypto_monero_hasher___del__(mp_obj_t self) {
  mp_obj_hasher_t *o = MP_OBJ_TO_PTR(self);
  memzero(&(o->h), sizeof(Hasher));
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_hasher___del___obj, mod_trezorcrypto_monero_hasher___del__);


//
// Scalar defs
//

// init256_modm_r
STATIC mp_obj_t mod_trezorcrypto_monero_init256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 2 ? 0 : -1;
    assert_scalar(res);

    if (n_args == 0) {
        set256_modm(MP_OBJ_SCALAR(res), 0);
    } else if (n_args > 0 && MP_OBJ_IS_SCALAR(args[1+off])) {
        copy256_modm(MP_OBJ_SCALAR(res), MP_OBJ_C_SCALAR(args[1+off]));
    } else if (n_args > 0 && MP_OBJ_IS_STR_OR_BYTES(args[1+off])) {
        mp_unpack_scalar(MP_OBJ_SCALAR(res), args[1+off]);
    } else if (n_args > 0 && mp_obj_is_integer(args[1+off])) {
        uint64_t v = mp_obj_get_uint64(args[1+off]);
        set256_modm(MP_OBJ_SCALAR(res), v);
    } else {
        mp_raise_ValueError("Invalid scalar def");
    }
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_init256_modm_obj, 0, 2, mod_trezorcrypto_monero_init256_modm);

//int check256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_check256_modm(const mp_obj_t arg){
    assert_scalar(arg);
    if (check256_modm(MP_OBJ_C_SCALAR(arg)) != 1){
        mp_raise_ValueError("Ed25519 scalar invalid");
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_check256_modm_obj, mod_trezorcrypto_monero_check256_modm);

//int iszero256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_iszero256_modm(const mp_obj_t arg){
    assert_scalar(arg);
    const int r = iszero256_modm(MP_OBJ_C_SCALAR(arg));
    return mp_obj_new_int(r);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_iszero256_modm_obj, mod_trezorcrypto_monero_iszero256_modm);

//int eq256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_eq256_modm(const mp_obj_t a, const mp_obj_t b){
    assert_scalar(a);
    assert_scalar(b);
    int r = eq256_modm(MP_OBJ_C_SCALAR(a), MP_OBJ_C_SCALAR(b));
    return MP_OBJ_NEW_SMALL_INT(r);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_monero_eq256_modm_obj, mod_trezorcrypto_monero_eq256_modm);

//int get256_modm_r
STATIC mp_obj_t mod_trezorcrypto_monero_get256_modm(const mp_obj_t arg){
    assert_scalar(arg);
    uint64_t v;
    if (!get256_modm(&v, MP_OBJ_C_SCALAR(arg))){
        mp_raise_ValueError("Ed25519 scalar too big");
    }
    return mp_obj_new_int_from_ull(v);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_get256_modm_obj, mod_trezorcrypto_monero_get256_modm);

// barrett_reduce256_modm_r, 1arg = lo, 2args = hi, lo, 3args = r, hi, lo
STATIC mp_obj_t mod_trezorcrypto_monero_reduce256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 3 ? 0 : -1;
    const bignum256modm hi_z = {0};
    const bignum256modm *hi = &hi_z;
    const bignum256modm *lo = NULL;

    assert_scalar(res);
    if (n_args > 1){
        assert_scalar(args[2+off]);
        lo = &MP_OBJ_C_SCALAR(args[2+off]);

        if (args[1+off] == NULL || MP_OBJ_IS_TYPE(args[1+off], &mp_type_NoneType)){
            ;
        } else {
            assert_scalar(args[1+off]);
            hi = &MP_OBJ_C_SCALAR(args[1+off]);
        }
    } else {
        assert_scalar(args[1+off]);
        lo = &MP_OBJ_C_SCALAR(args[1+off]);
    }

    barrett_reduce256_modm(MP_OBJ_SCALAR(res), *hi, *lo);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_reduce256_modm_obj, 1, 3, mod_trezorcrypto_monero_reduce256_modm);

//void add256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_add256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 3 ? 0 : -1;

    assert_scalar(res);
    assert_scalar(args[1+off]);
    assert_scalar(args[2+off]);
    add256_modm(MP_OBJ_SCALAR(res), MP_OBJ_C_SCALAR(args[1+off]), MP_OBJ_C_SCALAR(args[2+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_add256_modm_obj, 2, 3, mod_trezorcrypto_monero_add256_modm);

//void sub256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_sub256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 3 ? 0 : -1;

    assert_scalar(res);
    assert_scalar(args[1+off]);
    assert_scalar(args[2+off]);
    sub256_modm(MP_OBJ_SCALAR(res), MP_OBJ_C_SCALAR(args[1+off]), MP_OBJ_C_SCALAR(args[2+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_sub256_modm_obj, 2, 3, mod_trezorcrypto_monero_sub256_modm);

//void mulsub256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_mulsub256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 4 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 4 ? 0 : -1;

    assert_scalar(res);
    assert_scalar(args[1+off]);
    assert_scalar(args[2+off]);
    assert_scalar(args[3+off]);
    mulsub256_modm(MP_OBJ_SCALAR(res), MP_OBJ_C_SCALAR(args[1+off]), MP_OBJ_C_SCALAR(args[2+off]), MP_OBJ_C_SCALAR(args[3+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_mulsub256_modm_obj, 3, 4, mod_trezorcrypto_monero_mulsub256_modm);

//void contract256_modm_r
STATIC mp_obj_t mod_trezorcrypto_monero_pack256_modm(const mp_obj_t arg){
    assert_scalar(arg);
    uint8_t buff[32];
    contract256_modm(buff, MP_OBJ_C_SCALAR(arg));
    return mp_obj_new_bytes(buff, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_pack256_modm_obj, mod_trezorcrypto_monero_pack256_modm);

//void contract256_modm_r
STATIC mp_obj_t mod_trezorcrypto_monero_pack256_modm_into(const mp_obj_t arg, const mp_obj_t buf){
    assert_scalar(arg);
    mp_buffer_info_t bufm;
    mp_get_buffer_raise(buf, &bufm, MP_BUFFER_WRITE);
    if (bufm.len < 32) {
        mp_raise_ValueError("Buffer too small");
    }

    contract256_modm(bufm.buf, MP_OBJ_C_SCALAR(arg));
    return buf;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_monero_pack256_modm_into_obj, mod_trezorcrypto_monero_pack256_modm_into);

//expand256_modm_r
STATIC mp_obj_t mod_trezorcrypto_monero_unpack256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 2 ? 0 : -1;
    assert_scalar(res);
    mp_unpack_scalar(MP_OBJ_SCALAR(res), args[1+off]);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_unpack256_modm_obj, 1, 2, mod_trezorcrypto_monero_unpack256_modm);

//
// GE25519 Defs
//

//void ge25519_set_neutral(ge25519 *r);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_set_neutral(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 1 ? args[0] : mp_obj_new_ge25519();
    assert_ge25519(res);
    ge25519_set_neutral(&MP_OBJ_GE25519(res));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_set_neutral_obj, 0, 1, mod_trezorcrypto_monero_ge25519_set_neutral);

//void ge25519_set_xmr_h(ge25519 *r);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_set_xmr_h(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 1 ? args[0] : mp_obj_new_ge25519();
    assert_ge25519(res);
    ge25519_set_xmr_h(&MP_OBJ_GE25519(res));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_set_xmr_h_obj, 0, 1, mod_trezorcrypto_monero_ge25519_set_xmr_h);

//int ge25519_check(const ge25519 *r);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_check(const mp_obj_t arg){
  assert_ge25519(arg);
  if (ge25519_check(&MP_OBJ_C_GE25519(arg)) != 1){
    mp_raise_ValueError("Ed25519 point not on curve");
  }
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_ge25519_check_obj, mod_trezorcrypto_monero_ge25519_check);

//int ge25519_eq(const ge25519 *a, const ge25519 *b);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_eq(const mp_obj_t a, const mp_obj_t b){
    assert_ge25519(a);
    assert_ge25519(b);
    int r = ge25519_eq(&MP_OBJ_C_GE25519(a), &MP_OBJ_C_GE25519(b));
    return MP_OBJ_NEW_SMALL_INT(r);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_monero_ge25519_eq_obj, mod_trezorcrypto_monero_ge25519_eq);

//void ge25519_norm(ge25519 *r, const ge25519 *t);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_norm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    mp_obj_t src = n_args == 2 ? args[1] : args[0];
    assert_ge25519(res);
    assert_ge25519(src);
    ge25519_norm(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(src));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_norm_obj, 1, 2, mod_trezorcrypto_monero_ge25519_norm);

//void ge25519_add(ge25519 *r, const ge25519 *a, const ge25519 *b, unsigned char signbit);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_add(size_t n_args, const mp_obj_t *args){
    mp_int_t s = 0;
    int off = 0;
    mp_obj_t res = args[0];

    if (n_args == 2){                       // a, b
        off = -1;
    } else if (n_args == 3){                // r, a, b || a, b, s
        if (mp_obj_is_integer(args[2])){
            s = mp_obj_get_int(args[2]);
            off = -1;
        }
    } else if (n_args == 4){                // r, a, b, s
        s = mp_obj_get_int(args[3]);
    } else {
        mp_raise_ValueError(NULL);
    }

    if (off == -1){
        res = mp_obj_new_ge25519();
    }

    assert_ge25519(res);
    assert_ge25519(args[1+off]);
    assert_ge25519(args[2+off]);

    ge25519_add(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]), &MP_OBJ_C_GE25519(args[2+off]), s);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_add_obj, 3, 4, mod_trezorcrypto_monero_ge25519_add);

//void ge25519_double(ge25519 *r, const ge25519 *p);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_double(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    mp_obj_t src = n_args == 2 ? args[1] : args[0];
    assert_ge25519(src);
    assert_ge25519(res);

    ge25519_double(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(src));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_double_obj, 1, 2, mod_trezorcrypto_monero_ge25519_double);

//void ge25519_mul8(ge25519 *r, const ge25519 *p);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_mul8(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    mp_obj_t src = n_args == 2 ? args[1] : args[0];
    assert_ge25519(src);
    assert_ge25519(res);

    ge25519_mul8(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(src));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_mul8_obj, 1, 2, mod_trezorcrypto_monero_ge25519_mul8);

//void ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 4 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 4 ? 0 : -1;

    assert_ge25519(res);
    assert_ge25519(args[1+off]);
    assert_scalar(args[2+off]);
    assert_scalar(args[3+off]);

    ge25519_double_scalarmult_vartime(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]),
                                      MP_OBJ_C_SCALAR(args[2+off]), MP_OBJ_C_SCALAR(args[3+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime_obj, 3, 4, mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime);

//void ge25519_double_scalarmult_vartime2(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const ge25519 *p2, const bignum256modm s2);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime2(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 5 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 5 ? 0 : -1;

    assert_ge25519(res);
    assert_ge25519(args[1+off]);
    assert_scalar(args[2+off]);
    assert_ge25519(args[3+off]);
    assert_scalar(args[4+off]);

    ge25519_double_scalarmult_vartime2(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]),  MP_OBJ_C_SCALAR(args[2+off]),
                                       &MP_OBJ_C_GE25519(args[3+off]), MP_OBJ_C_SCALAR(args[4+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime2_obj, 4, 5, mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime2);

//void ge25519_scalarmult_base_wrapper(ge25519 *r, const bignum256modm s);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_scalarmult_base(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 2 ? 0 : -1;
    assert_ge25519(res);
    if (MP_OBJ_IS_SCALAR(args[1+off])){
        ge25519_scalarmult_base_wrapper(&MP_OBJ_GE25519(res), MP_OBJ_C_SCALAR(args[1+off]));
    } else if (mp_obj_is_integer(args[1+off])){
        bignum256modm mlt;
        set256_modm(mlt, mp_obj_get_int(args[1+off]));
        ge25519_scalarmult_base_wrapper(&MP_OBJ_GE25519(res), mlt);
    } else {
        mp_raise_ValueError("unknown base mult type");
    }

    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_scalarmult_base_obj, 1, 2, mod_trezorcrypto_monero_ge25519_scalarmult_base);

//void ge25519_scalarmult_wrapper(ge25519 *r, const ge25519 *P, const bignum256modm a);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_scalarmult(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 3 ? 0 : -1;
    assert_ge25519(res);
    assert_ge25519(args[1+off]);

    if (MP_OBJ_IS_SCALAR(args[2+off])){
        ge25519_scalarmult_wrapper(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]), MP_OBJ_C_SCALAR(args[2+off]));
    } else if (mp_obj_is_integer(args[2+off])){
        bignum256modm mlt;
        set256_modm(mlt, mp_obj_get_int(args[2+off]));
        ge25519_scalarmult_wrapper(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]), mlt);
    } else {
        mp_raise_ValueError("unknown mult type");
    }

    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_scalarmult_obj, 2, 3, mod_trezorcrypto_monero_ge25519_scalarmult);

//void ge25519_pack(unsigned char r[32], const ge25519 *p)
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_pack(const mp_obj_t arg){
    assert_ge25519(arg);
    uint8_t buff[32];
    ge25519_pack(buff, &MP_OBJ_C_GE25519(arg));

    return mp_obj_new_bytes(buff, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_ge25519_pack_obj, mod_trezorcrypto_monero_ge25519_pack);

//void ge25519_pack(unsigned char r[32], const ge25519 *p)
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_pack_into(const mp_obj_t arg, const mp_obj_t buf){
    assert_ge25519(arg);
    mp_buffer_info_t bufm;
    mp_get_buffer_raise(buf, &bufm, MP_BUFFER_WRITE);
    if (bufm.len < 32) {
        mp_raise_ValueError("Buffer too small");
    }

    ge25519_pack(bufm.buf, &MP_OBJ_C_GE25519(arg));
    return buf;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_monero_ge25519_pack_into_obj, mod_trezorcrypto_monero_ge25519_pack_into);

//int ge25519_unpack_vartime(ge25519 *r, const unsigned char *s)
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_unpack_vartime(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 2 ? 0 : -1;
    assert_ge25519(res);
    mp_unpack_ge25519(&MP_OBJ_GE25519(res), args[1+off]);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_unpack_vartime_obj, 1, 2, mod_trezorcrypto_monero_ge25519_unpack_vartime);

//
// XMR defs
//

// int xmr_base58_addr_encode_check(uint64_t tag, const uint8_t *data, size_t binsz, char *b58, size_t b58sz);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_base58_addr_encode_check(size_t n_args, const mp_obj_t *args){
    uint8_t out[128];
    mp_buffer_info_t data;
    mp_get_buffer_raise(args[1], &data, MP_BUFFER_READ);

    int sz = xmr_base58_addr_encode_check(mp_obj_get_int(args[0]), data.buf, data.len, (char *)out, sizeof(out));
    if (sz == 0){
        mp_raise_ValueError("b58 encoding error");
    }

    return mp_obj_new_bytes(out, sz);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_base58_addr_encode_check_obj, 2, 2, mod_trezorcrypto_monero_xmr_base58_addr_encode_check);

// int xmr_base58_addr_decode_check(const char *addr, size_t sz, uint64_t *tag, void *data, size_t datalen);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_base58_addr_decode_check(size_t n_args, const mp_obj_t *args){
    uint8_t out[128];
    uint64_t tag;

    mp_buffer_info_t data;
    mp_get_buffer_raise(args[0], &data, MP_BUFFER_READ);

    int sz = xmr_base58_addr_decode_check(data.buf, data.len, &tag, out, sizeof(out));
    if (sz == 0){
        mp_raise_ValueError("b58 decoding error");
    }

    mp_obj_tuple_t *tuple = MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
    tuple->items[0] = mp_obj_new_bytes(out, sz);
    tuple->items[1] = mp_obj_new_int_from_ull(tag);
    return MP_OBJ_FROM_PTR(tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_base58_addr_decode_check_obj, 1, 1, mod_trezorcrypto_monero_xmr_base58_addr_decode_check);

// xmr_random_scalar
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_random_scalar(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 1 ? args[0] : mp_obj_new_scalar();
    assert_scalar(res);
    xmr_random_scalar(MP_OBJ_SCALAR(res));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_random_scalar_obj, 0, 1, mod_trezorcrypto_monero_xmr_random_scalar);

//xmr_fast_hash
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_fast_hash(const mp_obj_t arg){
    uint8_t buff[32];
    mp_buffer_info_t data;
    mp_get_buffer_raise(arg, &data, MP_BUFFER_READ);
    xmr_fast_hash(buff, data.buf, data.len);
    return mp_obj_new_bytes(buff, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_xmr_fast_hash_obj, mod_trezorcrypto_monero_xmr_fast_hash);

//xmr_hash_to_ec
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_hash_to_ec(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 2 ? 0 : -1;
    mp_buffer_info_t data;
    assert_ge25519(res);
    mp_get_buffer_raise(args[1+off], &data, MP_BUFFER_READ);
    xmr_hash_to_ec(&MP_OBJ_GE25519(res), data.buf, data.len);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_hash_to_ec_obj, 1, 2, mod_trezorcrypto_monero_xmr_hash_to_ec);

//xmr_hash_to_scalar
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_hash_to_scalar(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 2 ? 0 : -1;
    mp_buffer_info_t data;
    assert_scalar(res);
    mp_get_buffer_raise(args[1+off], &data, MP_BUFFER_READ);
    xmr_hash_to_scalar(MP_OBJ_SCALAR(res), data.buf, data.len);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_hash_to_scalar_obj, 1, 2, mod_trezorcrypto_monero_xmr_hash_to_scalar);

//void xmr_derivation_to_scalar(bignum256modm s, const ge25519 * p, uint32_t output_index);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_derivation_to_scalar(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 3 ? 0 : -1;
    assert_scalar(res);
    assert_ge25519(args[1+off]);
    xmr_derivation_to_scalar(MP_OBJ_SCALAR(res), &MP_OBJ_C_GE25519(args[1+off]), mp_obj_get_int(args[2+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_derivation_to_scalar_obj, 2, 3, mod_trezorcrypto_monero_xmr_derivation_to_scalar);

//void xmr_generate_key_derivation(ge25519 * r, const ge25519 * A, const bignum256modm b);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_generate_key_derivation(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 3 ? 0 : -1;
    assert_ge25519(res);
    assert_ge25519(args[1+off]);
    assert_scalar(args[2+off]);
    xmr_generate_key_derivation(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]), MP_OBJ_C_SCALAR(args[2+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_generate_key_derivation_obj, 2, 3, mod_trezorcrypto_monero_xmr_generate_key_derivation);

//void xmr_derive_private_key(bignum256modm s, const ge25519 * deriv, uint32_t idx, const bignum256modm base);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_derive_private_key(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 4 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 4 ? 0 : -1;
    assert_scalar(res);
    assert_ge25519(args[1+off]);
    assert_scalar(args[3+off]);
    xmr_derive_private_key(MP_OBJ_SCALAR(res), &MP_OBJ_C_GE25519(args[1+off]), mp_obj_get_int(args[2+off]), MP_OBJ_C_SCALAR(args[3+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_derive_private_key_obj, 3, 4, mod_trezorcrypto_monero_xmr_derive_private_key);

//void xmr_derive_public_key(ge25519 * r, const ge25519 * deriv, uint32_t idx, const ge25519 * base);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_derive_public_key(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 4 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 4 ? 0 : -1;
    assert_ge25519(res);
    assert_ge25519(args[1+off]);
    assert_ge25519(args[3+off]);
    xmr_derive_public_key(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]), mp_obj_get_int(args[2+off]), &MP_OBJ_C_GE25519(args[3+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_derive_public_key_obj, 3, 4, mod_trezorcrypto_monero_xmr_derive_public_key);

//void xmr_add_keys2(ge25519 * r, const bignum256modm a, const bignum256modm b, const ge25519 * B);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_add_keys2(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 4 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 4 ? 0 : -1;
    assert_ge25519(res);
    assert_scalar(args[1+off]);
    assert_scalar(args[2+off]);
    assert_ge25519(args[3+off]);
    xmr_add_keys2(&MP_OBJ_GE25519(res), MP_OBJ_SCALAR(args[1+off]), MP_OBJ_SCALAR(args[2+off]), &MP_OBJ_C_GE25519(args[3+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_add_keys2_obj, 3, 4, mod_trezorcrypto_monero_xmr_add_keys2);

//void xmr_add_keys2_vartime(ge25519 * r, const bignum256modm a, const bignum256modm b, const ge25519 * B);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_add_keys2_vartime(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 4 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 4 ? 0 : -1;
    assert_ge25519(res);
    assert_scalar(args[1+off]);
    assert_scalar(args[2+off]);
    assert_ge25519(args[3+off]);
    xmr_add_keys2_vartime(&MP_OBJ_GE25519(res), MP_OBJ_SCALAR(args[1+off]), MP_OBJ_SCALAR(args[2+off]), &MP_OBJ_C_GE25519(args[3+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_add_keys2_vartime_obj, 3, 4, mod_trezorcrypto_monero_xmr_add_keys2_vartime);

//void xmr_add_keys3(ge25519 * r, const bignum256modm a, const ge25519 * A, const bignum256modm b, const ge25519 * B);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_add_keys3(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 5 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 5 ? 0 : -1;
    assert_ge25519(res);
    assert_scalar(args[1+off]);
    assert_ge25519(args[2+off]);
    assert_scalar(args[3+off]);
    assert_ge25519(args[4+off]);
    xmr_add_keys3(&MP_OBJ_GE25519(res),
                  MP_OBJ_SCALAR(args[1+off]), &MP_OBJ_C_GE25519(args[2+off]),
                  MP_OBJ_SCALAR(args[3+off]), &MP_OBJ_C_GE25519(args[4+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_add_keys3_obj, 4, 5, mod_trezorcrypto_monero_xmr_add_keys3);

//void xmr_add_keys3_vartime(ge25519 * r, const bignum256modm a, const ge25519 * A, const bignum256modm b, const ge25519 * B);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_add_keys3_vartime(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 5 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 5 ? 0 : -1;
    assert_ge25519(res);
    assert_scalar(args[1+off]);
    assert_ge25519(args[2+off]);
    assert_scalar(args[3+off]);
    assert_ge25519(args[4+off]);
    xmr_add_keys3_vartime(&MP_OBJ_GE25519(res),
                          MP_OBJ_SCALAR(args[1+off]), &MP_OBJ_C_GE25519(args[2+off]),
                          MP_OBJ_SCALAR(args[3+off]), &MP_OBJ_C_GE25519(args[4+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_add_keys3_vartime_obj, 4, 5, mod_trezorcrypto_monero_xmr_add_keys3_vartime);

//void xmr_get_subaddress_secret_key(bignum256modm r, uint32_t major, uint32_t minor, const bignum256modm m);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_get_subaddress_secret_key(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 4 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 4 ? 0 : -1;
    assert_scalar(res);
    assert_scalar(args[3+off]);
    xmr_get_subaddress_secret_key(MP_OBJ_SCALAR(res), mp_obj_get_int(args[1+off]), mp_obj_get_int(args[2+off]), MP_OBJ_C_SCALAR(args[3+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_get_subaddress_secret_key_obj, 3, 4, mod_trezorcrypto_monero_xmr_get_subaddress_secret_key);

//void xmr_gen_c(ge25519 * r, const bignum256modm a, uint64_t amount);
STATIC mp_obj_t mod_trezorcrypto_monero_xmr_gen_c(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 3 ? 0 : -1;
    assert_ge25519(res);
    assert_scalar(args[1+off]);
    xmr_gen_c(&MP_OBJ_GE25519(res), MP_OBJ_C_SCALAR(args[1+off]), mp_obj_get_uint64(args[2+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_xmr_gen_c_obj, 2, 3, mod_trezorcrypto_monero_xmr_gen_c);

/// def
STATIC mp_obj_t mod_trezorcrypto_monero_gen_range_proof(size_t n_args, const mp_obj_t *args) {
    uint64_t amount;
    ge25519 C;
    bignum256modm mask;

    if (sizeof(xmr_range_sig_t) != RSIG_SIZE){
        mp_raise_ValueError("rsize invalid");
    }

    mp_buffer_info_t rsig_buff;
    mp_get_buffer_raise(args[0], &rsig_buff, MP_BUFFER_WRITE);
    if (rsig_buff.len < RSIG_SIZE){
        mp_raise_ValueError("rsize buff too small");
    }

    xmr_range_sig_t * rsig = (xmr_range_sig_t*)rsig_buff.buf;
    bignum256modm * last_mask = NULL;
    amount = mp_obj_get_uint64(args[1]);
    if (n_args > 2 && MP_OBJ_IS_SCALAR(args[2])){
        last_mask = &MP_OBJ_SCALAR(args[2]);
    }

    if (n_args > 4){
        const size_t mem_limit = sizeof(bignum256modm)*64;
        mp_buffer_info_t buf_ai, buf_alpha;
        mp_get_buffer_raise(args[3], &buf_ai, MP_BUFFER_WRITE);
        mp_get_buffer_raise(args[4], &buf_alpha, MP_BUFFER_WRITE);
        if (buf_ai.len < mem_limit || buf_alpha.len < mem_limit) {
            mp_raise_ValueError("Buffer too small");
        }

        xmr_gen_range_sig_ex(rsig, &C, mask, amount, last_mask, buf_ai.buf, buf_alpha.buf);
    } else {
        xmr_gen_range_sig(rsig, &C, mask, amount, last_mask);
    }
    
    mp_obj_tuple_t *tuple = MP_OBJ_TO_PTR(mp_obj_new_tuple(3, NULL));
    tuple->items[0] = mp_obj_from_ge25519(&C);
    tuple->items[1] = mp_obj_from_scalar(mask);
    tuple->items[2] = args[0];
    return MP_OBJ_FROM_PTR(tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_gen_range_proof_obj, 2, 5, mod_trezorcrypto_monero_gen_range_proof);


/// def
STATIC mp_obj_t mod_trezorcrypto_ct_equals(const mp_obj_t a, const mp_obj_t b){
    mp_buffer_info_t buff_a, buff_b;
    mp_get_buffer_raise(a, &buff_a, MP_BUFFER_READ);
    mp_get_buffer_raise(b, &buff_b, MP_BUFFER_READ);

    if (buff_a.len != buff_b.len) {
      return MP_OBJ_NEW_SMALL_INT(0);
    }

    int r = ed25519_verify(buff_a.buf, buff_b.buf, buff_a.len);
    return MP_OBJ_NEW_SMALL_INT(r);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_ct_equals_obj, mod_trezorcrypto_ct_equals);

// Hasher
STATIC mp_obj_t mod_trezorcrypto_monero_hasher_update(mp_obj_t self, const mp_obj_t arg){
    mp_obj_hasher_t *o = MP_OBJ_TO_PTR(self);
    mp_buffer_info_t buff;
    mp_get_buffer_raise(arg, &buff, MP_BUFFER_READ);
    if (buff.len > 0) {
      xmr_hasher_update(&o->h, buff.buf, buff.len);
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_monero_hasher_update_obj, mod_trezorcrypto_monero_hasher_update);

STATIC mp_obj_t mod_trezorcrypto_monero_hasher_digest(mp_obj_t self){
    mp_obj_hasher_t *o = MP_OBJ_TO_PTR(self);
    uint8_t out[SHA3_256_DIGEST_LENGTH];
    Hasher ctx;
    memcpy(&ctx, &(o->h), sizeof(Hasher));

    xmr_hasher_final(&ctx, out);
    memset(&ctx, 0, sizeof(SHA3_CTX));
    return mp_obj_new_bytes(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_hasher_digest_obj, mod_trezorcrypto_monero_hasher_digest);

STATIC mp_obj_t mod_trezorcrypto_monero_hasher_copy(mp_obj_t self){
    mp_obj_hasher_t *o = MP_OBJ_TO_PTR(self);
    mp_obj_hasher_t *cp = m_new_obj(mp_obj_hasher_t);
    cp->base.type = o->base.type;
    memcpy(&(cp->h), &(o->h), sizeof(Hasher));
    return MP_OBJ_FROM_PTR(o);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_hasher_copy_obj, mod_trezorcrypto_monero_hasher_copy);


//
// Type defs
//

STATIC const mp_rom_map_elem_t mod_trezorcrypto_monero_ge25519_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519___del___obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_monero_ge25519_locals_dict, mod_trezorcrypto_monero_ge25519_locals_dict_table);

STATIC const mp_obj_type_t mod_trezorcrypto_monero_ge25519_type = {
    { &mp_type_type },
    .name = MP_QSTR_ge25519,
    .make_new = mod_trezorcrypto_monero_ge25519_make_new,
    .locals_dict = (void*)&mod_trezorcrypto_monero_ge25519_locals_dict,
};

STATIC const mp_rom_map_elem_t mod_trezorcrypto_monero_bignum256modm_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&mod_trezorcrypto_monero_bignum256modm___del___obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_monero_bignum256modm_locals_dict, mod_trezorcrypto_monero_bignum256modm_locals_dict_table);


STATIC const mp_obj_type_t mod_trezorcrypto_monero_bignum256modm_type = {
    { &mp_type_type },
    .name = MP_QSTR_bignum256modm,
    .make_new = mod_trezorcrypto_monero_bignum256modm_make_new,
    .locals_dict = (void*)&mod_trezorcrypto_monero_bignum256modm_locals_dict,
};

STATIC const mp_rom_map_elem_t mod_trezorcrypto_monero_hasher_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&mod_trezorcrypto_monero_hasher_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&mod_trezorcrypto_monero_hasher_digest_obj) },
    { MP_ROM_QSTR(MP_QSTR_copy), MP_ROM_PTR(&mod_trezorcrypto_monero_hasher_copy_obj) },
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&mod_trezorcrypto_monero_hasher___del___obj) },
    { MP_ROM_QSTR(MP_QSTR_block_size), MP_OBJ_NEW_SMALL_INT(SHA3_256_BLOCK_LENGTH) },
    { MP_ROM_QSTR(MP_QSTR_digest_size), MP_OBJ_NEW_SMALL_INT(SHA3_256_DIGEST_LENGTH) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_monero_hasher_locals_dict, mod_trezorcrypto_monero_hasher_locals_dict_table);


STATIC const mp_obj_type_t mod_trezorcrypto_monero_hasher_type = {
    { &mp_type_type },
    .name = MP_QSTR_hasher,
    .make_new = mod_trezorcrypto_monero_hasher_make_new,
    .locals_dict = (void*)&mod_trezorcrypto_monero_hasher_locals_dict,
};

STATIC const mp_rom_map_elem_t mod_trezorcrypto_monero_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_monero) },
    { MP_ROM_QSTR(MP_QSTR_init256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_init256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_check256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_check256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_iszero256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_iszero256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_eq256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_eq256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_get256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_get256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_reduce256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_reduce256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_add256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_add256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_sub256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_sub256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_mulsub256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_mulsub256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_pack256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_pack256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_pack256_modm_into), MP_ROM_PTR(&mod_trezorcrypto_monero_pack256_modm_into_obj) },
    { MP_ROM_QSTR(MP_QSTR_unpack256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_unpack256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_set_neutral), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_set_neutral_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_set_h), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_set_xmr_h_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_pack), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_pack_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_pack_into), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_pack_into_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_unpack_vartime), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_unpack_vartime_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_check), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_check_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_eq), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_eq_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_norm), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_norm_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_add), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_double), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_double_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_mul8), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_mul8_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_double_scalarmult_vartime), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_double_scalarmult_vartime2), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime2_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_scalarmult_base), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_scalarmult_base_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_scalarmult), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_scalarmult_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_base58_addr_encode_check), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_base58_addr_encode_check_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_base58_addr_decode_check), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_base58_addr_decode_check_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_random_scalar), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_random_scalar_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_fast_hash), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_fast_hash_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_hash_to_ec), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_hash_to_ec_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_hash_to_scalar), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_hash_to_scalar_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_derivation_to_scalar), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_derivation_to_scalar_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_generate_key_derivation), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_generate_key_derivation_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_derive_private_key), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_derive_private_key_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_derive_public_key), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_derive_public_key_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_add_keys2), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_add_keys2_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_add_keys2_vartime), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_add_keys2_vartime_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_add_keys3), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_add_keys3_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_add_keys3_vartime), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_add_keys3_vartime_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_get_subaddress_secret_key), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_get_subaddress_secret_key_obj) },
    { MP_ROM_QSTR(MP_QSTR_xmr_gen_c), MP_ROM_PTR(&mod_trezorcrypto_monero_xmr_gen_c_obj) },
    { MP_ROM_QSTR(MP_QSTR_gen_range_proof), MP_ROM_PTR(&mod_trezorcrypto_monero_gen_range_proof_obj) },
    { MP_ROM_QSTR(MP_QSTR_ct_equals), MP_ROM_PTR(&mod_trezorcrypto_ct_equals_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_monero_globals, mod_trezorcrypto_monero_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_monero_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mod_trezorcrypto_monero_globals,
};
