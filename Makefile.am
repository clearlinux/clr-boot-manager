ACLOCAL_AMFLAGS = -I m4



EXTRA_DIST = ${top_srcdir}/README.md \
	     ${top_srcdir}/LICENSE.LGPL2.1 \
	     ${top_srcdir}/HACKING \
	     ${top_srcdir}/findstatic.pl \
	     ${top_srcdir}/tests/data/hashfile \
	     ${top_srcdir}/tests/data/blobfile \
	     ${top_srcdir}/test-init.sh \
	     ${top_srcdir}/sgcheck.suppressions

NULL =
CLEANFILES =

# For local distcheck testing
#DISTCHECK_CONFIGURE_FLAGS = \
#	--with-bootloader=goofiboot

AM_CFLAGS = -fstack-protector -Wall -pedantic \
        -Wstrict-prototypes -Wundef -fno-common \
        -Werror-implicit-function-declaration \
        -Wformat -Wformat-security -Werror=format-security \
        -Wno-conversion -Wunused-variable -Wunreachable-code \
        -Wall -W -D_FORTIFY_SOURCE=2 \
        -std=c99 \
        -DSYSCONFDIR=\"$(sysconfdir)\"

AM_CPPFLAGS = \
	-I $(top_srcdir)/src \
	-DTOP_DIR=\"$(abs_top_srcdir)\" \
	-DTOP_BUILD_DIR=\"$(abs_top_builddir)\"

AUTOMAKE_OPTIONS = color-tests parallel-tests

if COVERAGE
coverage:
	mkdir -p coverage
	lcov --compat-libtool --directory . --capture --output-file coverage/report
	genhtml -o coverage/ coverage/report
AM_CFLAGS += --coverage
endif

noinst_LTLIBRARIES = \
	libnica.la       \
	libcbm.la

libnica_la_SOURCES =     \
	src/nica/array.c     \
	src/nica/array.h     \
	src/nica/files.c     \
	src/nica/files.h     \
	src/nica/hashmap.c   \
	src/nica/hashmap.h   \
	src/nica/inifile.c   \
	src/nica/inifile.h   \
	src/nica/list.c      \
	src/nica/list.h      \
	src/nica/macros.h    \
	src/nica/util.c      \
	src/nica/util.h

libnica_la_CFLAGS =      \
	$(AM_CFLAGS)         \
	-DLIBNICA_INTERNAL   \
	-fvisibility=hidden


bin_PROGRAMS = clr-boot-manager

libcbm_la_SOURCES =					\
	src/bootloader.h				\
	src/bootloaders/systemd-class.h \
	src/bootloaders/systemd-class.c \
	src/bootloaders/systemd-boot.c	\
	src/bootloaders/gummiboot.c		\
	src/bootloaders/goofiboot.c		\
	src/util.h						\
	src/util.c						\
	src/files.h						\
	src/files.c						\
	src/bootman.h					\
	src/bootman.c

libcbm_la_CFLAGS =		\
	$(CRYPTO_CFLAGS)	\
	$(BLKID_CFLAGS)		\
	$(AM_CFLAGS)

libcbm_LIBADD =			\
	libnica.la

clr_boot_manager_SOURCES =  \
	src/cli.h 				\
	src/cli.c				\
	src/ops/update.h		\
	src/ops/update.c		\
	src/ops/timeout.h		\
	src/ops/timeout.c		\
	src/main.c

clr_boot_manager_CFLAGS = \
	$(CRYPTO_CFLAGS) \
	$(BLKID_CFLAGS) \
	$(AM_CFLAGS)

clr_boot_manager_LDADD = \
	$(CRYPTO_LIBS) \
	$(BLKID_LIBS) \
	libnica.la \
	libcbm.la

install-exec-hook:
	perl ${top_srcdir}/findstatic.pl ${top_builddir}/src/*.o ${top_builddir}/src/*/*.o | grep -v Checking ||:

# Test suites
AM_TESTS_ENVIRONMENT = \
	eval $(srcdir)/test-init.sh "${top_srcdir}" "$(top_builddir)" "$(bootdir)";

distclean-local:
	rm -rf ${top_builddir}/tests/dummy_install

TESTS = \
	check_core \
	check_files

check_PROGRAMS = $(TESTS)

check_core_SOURCES = \
	tests/check-core.c

check_core_CFLAGS = \
	$(CRYPTO_CFLAGS) \
	$(BLKID_CFLAGS) \
	$(CHECK_CFLAGS) \
	$(AM_CFLAGS)

check_core_LDADD = \
	$(CRYPTO_LIBS) \
	$(BLKID_LIBS) \
	$(CHECK_LIBS) \
	libcbm.la	  \
	libnica.la

check_files_SOURCES = \
	tests/check-files.c

check_files_CFLAGS = \
	$(CRYPTO_CFLAGS) \
	$(BLKID_CFLAGS) \
	$(CHECK_CFLAGS) \
	$(AM_CFLAGS)

check_files_LDADD = \
	$(CRYPTO_LIBS)	\
	$(BLKID_LIBS)	\
	$(CHECK_LIBS)	\
	libcbm.la		\
	libnica.la

@VALGRIND_CHECK_RULES@


VALGRIND_SUPPRESSIONS_FILES = \
	${abs_top_srcdir}/sgcheck.suppressions
