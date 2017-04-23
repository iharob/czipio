AC_INIT([czipio], [0.1.0], [iharob@gmail.com])
AM_INIT_AUTOMAKE([subdir-objects])

AC_CONFIG_MACRO_DIRS([m4])

AC_PROG_LIBTOOL
AC_PROG_CC

PKG_CHECK_MODULES([SSL], [libssl >= 1.0])
PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.0])
PKG_CHECK_MODULES([ZLIB], [zlib >= 1.2.7])

AC_SUBST(SSL_LIBS)
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(ZLIB_LIBS)

CFLAGS="-fPIC"
LDFLAGS=
AC_ARG_ENABLE(
    [debug],
    AS_HELP_STRING([--enable-debug], [Enable debug output and symbols]),
    [
        CFLAGS+=" -O0 -g3 -pthread -Wall -Werror -Wstrict-aliasing -Wno-unused-function"
        LDLAGS+=" -g3 -O0"
    ],
    [
        LDLAGS+=" -O2"
    ]
)
AR_FLAGS="cr"
AC_CONFIG_FILES([
    Makefile
    czipio.pc
])
AC_OUTPUT
