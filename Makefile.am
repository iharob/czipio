AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libczipio.la

libczipio_la_SOURCES =       \
    include/czipio-cipher.h  \
    include/czipio-utils.h   \
    include/czipio-entry.h   \
    include/czipio.h         \
    src/czipio-cipher.c      \
    src/czipio-utils.c       \
    src/czipio-entry.c       \
    src/czipio.c

libczipio_la_CFLAGS = $(CFLAGS)       \
	-I$(top_srcdir)/utils/include \
	-I$(srcdir)/include

libczipio_la_LIBADD =     \
	$(LDFLAGS)        \
        $(SSL_LIBS)       \
	$(CRYPTO_LIBS)    \
	$(ZLIB_LIBS)

pkgconfigdir = $(libdir)/pkgconfig/
pkgconfig_DATA = czipio.pc

czipiodir = $(includedir)/czipio
czipio_HEADERS =        \
    include/czipio-cipher.h \
    include/czipio-entry.h  \
    include/czipio-utils.h  \
    include/czipio.h
