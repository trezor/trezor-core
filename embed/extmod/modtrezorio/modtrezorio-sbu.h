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

#include "sbu.h"

#define SBU_DEFAULT_READ_TIMEOUT 10000
#define SBU_DEFAULT_WRITE_TIMEOUT 10000

/// class SBU:
///     '''
///     '''
typedef struct _mp_obj_SBU_t {
    mp_obj_base_t base;
} mp_obj_SBU_t;

/// def __init__(self) -> None:
///     '''
///     Initialize SBU in GPIO mode (UART disabled)
///     '''
STATIC mp_obj_t mod_trezorio_SBU_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_obj_SBU_t *o = m_new_obj(mp_obj_SBU_t);
    o->base.type = type;
    sbu_init();
    return MP_OBJ_FROM_PTR(o);
}

/// def read(buffer: bytearray, timeout=10000) -> int:
///     '''
///     Reads from SBU UART (timeout is in milliseconds)
///     '''
STATIC mp_obj_t mod_trezorio_SBU_read(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t b;
    mp_get_buffer_raise(args[1], &b, MP_BUFFER_WRITE);
    uint32_t timeout = n_args > 2 ? mp_obj_get_int(args[2]) : SBU_DEFAULT_READ_TIMEOUT;
    int res = sbu_read(b.buf, b.len, timeout);
    return MP_OBJ_NEW_SMALL_INT(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorio_SBU_read_obj, 2, 3, mod_trezorio_SBU_read);

/// def write(buffer: bytearray, timeout=10000) -> None:
///     '''
///     Writes to SBU UART (timeout is in milliseconds)
///     '''
STATIC mp_obj_t mod_trezorio_SBU_write(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t b;
    mp_get_buffer_raise(args[1], &b, MP_BUFFER_READ);
    uint32_t timeout = n_args > 2 ? mp_obj_get_int(args[2]) : SBU_DEFAULT_WRITE_TIMEOUT;
    sbu_write(b.buf, b.len, timeout);
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorio_SBU_write_obj, 2, 3, mod_trezorio_SBU_write);

/// def set_uart(self, serial: bool) -> None:
///     '''
///     Enables/disables SBU UART (disabled = SBU pins are GPIO)
///     '''
STATIC mp_obj_t mod_trezorio_SBU_set_uart(mp_obj_t self, mp_obj_t serial) {
    if (mp_obj_is_true(serial)) {
        sbu_uart_on();
    } else {
        sbu_uart_off();
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorio_SBU_set_uart_obj, mod_trezorio_SBU_set_uart);

/// def set_pins(self, sbu1: bool, sbu2: bool) -> None:
///     '''
///     Set GPIO values for SBU1 and SBU2 pins (if UART is disabled)
///     '''
STATIC mp_obj_t mod_trezorio_SBU_set_pins(mp_obj_t self, mp_obj_t sbu1, mp_obj_t sbu2) {
    sbu_set_pins(sectrue * mp_obj_is_true(sbu1), sectrue * mp_obj_is_true(sbu2));
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorio_SBU_set_pins_obj, mod_trezorio_SBU_set_pins);

STATIC const mp_rom_map_elem_t mod_trezorio_SBU_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_read), MP_ROM_PTR(&mod_trezorio_SBU_read_obj) },
    { MP_ROM_QSTR(MP_QSTR_write), MP_ROM_PTR(&mod_trezorio_SBU_write_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_uart), MP_ROM_PTR(&mod_trezorio_SBU_set_uart_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_pins), MP_ROM_PTR(&mod_trezorio_SBU_set_pins_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorio_SBU_locals_dict, mod_trezorio_SBU_locals_dict_table);

STATIC const mp_obj_type_t mod_trezorio_SBU_type = {
    { &mp_type_type },
    .name = MP_QSTR_SBU,
    .make_new = mod_trezorio_SBU_make_new,
    .locals_dict = (void*)&mod_trezorio_SBU_locals_dict,
};
