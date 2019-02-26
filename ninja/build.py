#!/usr/bin/python

import os
import ninja
import source


def common(w, debug=True, optimize=True):
    w.variable("builddir", "build/unix")

    # executables
    w.variable("cc", "gcc")
    w.variable("py", "python")

    # compiling
    w.variable(
        "cflags_common",
        "-std=gnu99 "
        "-Wall "
        "-Werror "
        "-Wno-sequence-point "
        "-Wuninitialized "
        "-fdata-sections "
        "-ffunction-sections",
    )
    w.variable(
        "cflags_inc",
        "-I. "
        "-Ivendor/micropython "
        "-Ivendor/micropython/ports/unix "
        "-Iembed/unix "
        "-Iembed/extmod/modtrezorui "
        "-I$builddir "
        "-Ivendor/trezor-crypto",
    )
    w.variable(
        "cflags_def",
        "-DTREZOR_MODEL=T "
        "-DTREZOR_EMULATOR "
        '-DMP_CONFIGFILE="embed/unix/mpconfigport.h" '
        "-DMICROPY_USE_READLINE "
        "-DAES_128 "
        "-DAES_192 "
        "-DUSE_KECCAK=1 "
        "-DUSE_ETHEREUM=1 "
        "-DUSE_MONERO=1 "
        "-DUSE_CARDANO=1 "
        "-DUSE_NEM=1",
    )
    w.variable("cflags_debug", "-g3" if debug else "")
    w.variable("cflags_opt", "-Os" if optimize else "")
    w.variable(
        "cflags", "$cflags_opt $cflags_debug $cflags_common $cflags_inc $cflags_def"
    )
    w.rule(
        "cc", "$cc $cflags -c $in -o $out -MMD -MF $out.d", deps="gcc", depfile="$out.d"
    )

    # linking
    w.variable("ldflags", "-L/usr/local/lib -lSDL2 -lSDL2_image -lm")
    w.rule("ld", "$cc $ldflags $in -o $out")


def micropython(w):
    for s in source.micropython:
        w.build(build_object(s), "cc", s, implicit="$qstr")


def unix(w):
    for s in source.unix:
        w.build(build_object(s), "cc", s, implicit="$qstr")


def extmod(w):
    for s in (
        source.modtrezorconfig
        + source.modtrezorcrypto
        + source.modtrezorio
        + source.modtrezorui
        + source.modtrezorutils
        + source.modtime
    ):
        w.build(build_object(s), "cc", s, implicit="$qstr")


def version(w):
    w.rule("version", "$py vendor/micropython/py/makeversionhdr.py $out")
    w.build("$builddir/genhdr/mpversion.h", "version")


def qstrings(w):
    w.rule(
        "qstr_collect",
        "$cc $cflags $in -E -DNO_QSTR | $py site_scons/site_tools/micropython/qstrdefs.py > $out",
    )
    w.rule(
        "qstr_preprocess",
        """cat $in | sed 's/^Q(.*)/"&"/' | $cc $cflags -E - $ | sed 's/^"\(Q(.*)\)"/\\1/' > $out""",
    )
    w.rule("qstr_generate", "$py vendor/micropython/py/makeqstrdata.py $in > $out")

    w.build(
        "$builddir/genhdr/qstrdefs.collected.h",
        "qstr_collect",
        (
            source.micropython
            + source.unix
            + source.modtrezorconfig
            + source.modtrezorcrypto
            + source.modtrezorio
            + source.modtrezorui
            + source.modtrezorutils
            + source.modtime
        ),
        implicit="$builddir/genhdr/mpversion.h",
    )
    w.build(
        "$builddir/genhdr/qstrdefs.preprocessed.h",
        "qstr_preprocess",
        "vendor/micropython/py/qstrdefs.h $builddir/genhdr/qstrdefs.collected.h",
    )
    w.build(
        "$builddir/genhdr/qstrdefs.generated.h",
        "qstr_generate",
        "$builddir/genhdr/qstrdefs.preprocessed.h",
    )

    w.variable("qstr", "$builddir/genhdr/qstrdefs.generated.h")


def build_object(path):
    base, ext = os.path.splitext(path)
    return "$builddir/%s.o" % base


with open("build_unix_debug.ninja", "w") as of:
    writer = ninja.Writer(of, 1024)
    common(writer)
    qstrings(writer)
    micropython(writer)
    extmod(writer)
    unix(writer)
    version(writer)
