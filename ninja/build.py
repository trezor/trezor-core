#!/usr/bin/python

import os
import ninja
import source


def common(w):
    w.variable("builddir", "build/unix")

    w.variable("cc", "gcc")
    w.variable("py", "python")

    w.variable("cflags_common", "-std=gnu99 -Wall -Werror -Wno-sequence-point -Wuninitialized -fdata-sections -ffunction-sections")
    w.variable("cflags_debug", "-g3")
    w.variable("cflags_opt", "-Os")
    w.variable("cflags_inc", "-I. -Ivendor/micropython -Ivendor/micropython/ports/unix -Iembed/unix -Iembed/extmod/modtrezorui -I$builddir -Ivendor/trezor-crypto")
    w.variable("cflags_def", "-DTREZOR_MODEL=T -DTREZOR_EMULATOR -DMP_CONFIGFILE=\"embed/unix/mpconfigport.h\" -DMICROPY_USE_READLINE -DAES_128 -DAES_192 -DUSE_KECCAK=1 -DUSE_ETHEREUM=1 -DUSE_MONERO=1 -DUSE_CARDANO=1 -DUSE_NEM=1")
    w.variable("cflags", "$cflags_opt $cflags_debug $cflags_common $cflags_inc $cflags_def")
    w.rule("cc", "$cc $cflags -c $in -o $out -MMD -MF $out.d", deps="gcc", depfile="$out.d")

    w.variable("ldflags", "-L/usr/local/lib -lSDL2 -lSDL2_image -lm")
    w.rule("ld", "$cc $ldflags $in -o $out")


def micropython(w):
    build(w, source.micropython, "cc", implicit="$qstr")


def unix(w):
    build(w, source.unix, "cc", implicit="$qstr")


def extmod(w):
    build(w, source.modtrezorconfig, "cc", implicit="$qstr")
    build(w, source.modtrezorcrypto, "cc", implicit="$qstr")
    build(w, source.modtrezorio, "cc", implicit="$qstr")
    build(w, source.modtrezorui, "cc", implicit="$qstr")
    build(w, source.modtrezorutils, "cc", implicit="$qstr")
    build(w, source.modtime, "cc", implicit="$qstr")


def build(w, srcs, rule, **kwargs):
    for src in srcs:
        w.build("$builddir/%s.o" % os.path.splitext(src)[0], rule, src, **kwargs)


with open("build_unix_debug.ninja", "w") as of:
    w = ninja.Writer(of, 1024)
    common(w)
    micropython(w)
    extmod(w)
    unix(w)
