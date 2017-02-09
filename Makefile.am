ACLOCAL_AMFLAGS = -I m4



EXTRA_DIST = ${top_srcdir}/README.md \
	     ${top_srcdir}/LICENSE.LGPL2.1 \
	     ${top_srcdir}/HACKING \
	     ${top_srcdir}/findstatic.pl \
	     ${top_srcdir}/tests/data/blobfile \
	     ${top_srcdir}/tests/data/match \
	     ${top_srcdir}/tests/data/match1 \
	     ${top_srcdir}/tests/data/nomatch1 \
	     ${top_srcdir}/tests/data/nomatch2 \
	     ${top_srcdir}/tests/data/clear.os-release \
	     ${top_srcdir}/tests/data/solus.os-release \
	     ${top_srcdir}/tests/data/cmdline/comments \
	     ${top_srcdir}/tests/data/cmdline/mangledmess \
	     ${top_srcdir}/tests/data/cmdline/multi \
	     ${top_srcdir}/tests/data/cmdline/oneline \
	     ${top_srcdir}/tests/data/etc/kernel/cmdline \
	     ${top_srcdir}/tests/data/etc/kernel/cmdline.d/10_first.conf \
	     ${top_srcdir}/tests/data/etc/kernel/cmdline.d/20_second.conf \
	     ${top_srcdir}/tests/data/etc/kernel/cmdline.d/30_third.conf \
	     ${top_srcdir}/sgcheck.suppressions \
	     ${top_srcdir}/data/clr-boot-manager-booted.service \
	     ${top_srcdir}/compat/kernel_updater.sh \
	     ${top_srcdir}/compat/systemdboot_updater.sh \
	     ${top_srcdir}/compat/gummiboot_updaters.sh \
	     ${top_srcdir}/man/clr-boot-manager.1


if COMPAT_SCRIPTS
bin_SCRIPTS = \
	compat/kernel_updater.sh \
	compat/systemdboot_updater.sh \
	compat/gummiboot_updaters.sh
endif

NULL =
CLEANFILES =

DISTCHECK_CONFIGURE_FLAGS = \
      --with-systemdsystemunitdir="${distdir}/${libdir}/systemd/system"


AM_CFLAGS = -fstack-protector -Wall -pedantic \
        -Wstrict-prototypes -Wundef -fno-common \
        -Werror-implicit-function-declaration \
        -Wformat -Wformat-security -Werror=format-security \
        -Wconversion -Wunused-variable -Wunreachable-code \
        -Wall -W -D_FORTIFY_SOURCE=2 \
        -std=c11 \
        -DSYSCONFDIR=\"$(sysconfdir)\"

AM_CPPFLAGS = 					 \
	-I $(top_srcdir)/src			 \
	-I $(top_srcdir)/src/bootman		 \
	-I $(top_srcdir)/src/cli		 \
	-I $(top_srcdir)/src/bootloaders	 \
	-I $(top_srcdir)/src/lib		 \
	-I $(top_srcdir)/src/libnica/src/include \
	-DTOP_DIR=\"$(abs_top_srcdir)\"		 \
	-DTOP_BUILD_DIR=\"$(abs_top_builddir)\"

AUTOMAKE_OPTIONS = color-tests parallel-tests

SUBDIRS = src/libnica

if COVERAGE
coverage:
	mkdir -p coverage
	lcov --compat-libtool --directory . --capture --output-file coverage/report
	lcov --remove coverage/report 'tests/*' '/usr/*' --output-file coverage/report
	genhtml -o coverage/ coverage/report

AM_CFLAGS += --coverage
endif

noinst_LTLIBRARIES = \
	libcbm.la

bin_PROGRAMS = clr-boot-manager

libcbm_la_SOURCES =			\
	src/bootloaders/bootloader.h	\
	src/bootloaders/systemd-class.h \
	src/bootloaders/systemd-class.c \
	src/bootloaders/systemd-boot.c	\
	src/bootloaders/gummiboot.c	\
	src/bootloaders/goofiboot.c	\
	src/bootloaders/syslinux.c	\
	src/bootman/bootman.h		\
	src/bootman/bootman_private.h	\
	src/bootman/bootman.c		\
	src/bootman/kernel.c		\
	src/bootman/sysconfig.c		\
	src/bootman/timeout.c		\
	src/bootman/update.c		\
	src/lib/blkid_stub.h            \
	src/lib/blkid_stub.c            \
	src/lib/cmdline.h               \
	src/lib/cmdline.c               \
	src/lib/files.h			\
	src/lib/files.c			\
	src/lib/os-release.h            \
	src/lib/os-release.c            \
	src/lib/log.h			\
	src/lib/log.c			\
	src/lib/probe.h                 \
	src/lib/probe.c                 \
	src/lib/system_stub.h           \
	src/lib/system_stub.c           \
	src/lib/writer.h                \
	src/lib/writer.c                \
	src/lib/util.h

libcbm_la_CFLAGS =		\
	-D_BOOTMAN_INTERNAL_	\
	$(BLKID_CFLAGS)		\
	$(AM_CFLAGS)

libcbm_la_LIBADD =			\
	src/libnica/libnica.la

clr_boot_manager_SOURCES =		\
	src/cli/cli.h 			\
	src/cli/cli.c			\
	src/cli/ops/update.h		\
	src/cli/ops/update.c		\
	src/cli/ops/timeout.h		\
	src/cli/ops/timeout.c		\
	src/cli/ops/report_booted.h	\
	src/cli/ops/report_booted.c	\
	src/cli/main.c

clr_boot_manager_CFLAGS =	\
	$(BLKID_CFLAGS)		\
	$(AM_CFLAGS)

clr_boot_manager_LDADD =	\
	libcbm.la		\
	src/libnica/libnica.la		\
	$(BLKID_LIBS)

install-exec-hook:
	perl ${top_srcdir}/findstatic.pl ${top_builddir}/src/*.o ${top_builddir}/src/*/*.o | grep -v Checking ||:

# Install systemd unit
if SYSTEMD
systemdsystemunitdir = @SYSTEMD_SYSTEMUNITDIR@
dist_systemdsystemunit_DATA = ${top_srcdir}/data/clr-boot-manager-booted.service
endif

manpagesdir = $(mandir)/man1
manpages_DATA = \
	man/clr-boot-manager.1

distclean-local:
	rm -rf ${top_builddir}/tests/update_playground

TESTS = 		\
	check_core 	\
	check_cmdline   \
	check_files 	\
	check_legacy    \
	check_os_release

check_PROGRAMS = $(TESTS)

check_core_SOURCES =		\
	tests/check-core.c	\
	tests/blkid-harness.h   \
	tests/system-harness.h  \
	tests/harness.h		\
	tests/harness.c

check_core_CFLAGS =		\
	$(BLKID_CFLAGS)		\
	$(CHECK_CFLAGS)		\
	$(AM_CFLAGS)

check_core_LDADD =	\
	libcbm.la	\
	src/libnica/libnica.la	\
	$(BLKID_LIBS)	\
	$(CHECK_LIBS)

check_cmdline_SOURCES =		\
	tests/check-cmdline.c

check_cmdline_CFLAGS =		\
	$(BLKID_CFLAGS)		\
	$(CHECK_CFLAGS)		\
	$(AM_CFLAGS)

check_cmdline_LDADD =	\
	libcbm.la	\
	src/libnica/libnica.la	\
	$(BLKID_LIBS)	\
	$(CHECK_LIBS)

check_files_SOURCES = \
	tests/check-files.c 	\
	tests/harness.h		\
	tests/harness.c

check_files_CFLAGS =		\
	$(BLKID_CFLAGS)		\
	$(CHECK_CFLAGS)		\
	$(AM_CFLAGS)

check_files_LDADD =	\
	libcbm.la	\
	src/libnica/libnica.la	\
	$(BLKID_LIBS)	\
	$(CHECK_LIBS)

check_legacy_SOURCES = \
	tests/check-legacy.c 	\
	tests/blkid-harness.h   \
	tests/system-harness.h  \
	tests/harness.h		\
	tests/harness.c

check_legacy_CFLAGS =		\
	$(BLKID_CFLAGS)		\
	$(CHECK_CFLAGS)		\
	$(AM_CFLAGS)

check_legacy_LDADD =	\
	libcbm.la	\
	src/libnica/libnica.la	\
	$(BLKID_LIBS)	\
	$(CHECK_LIBS)

check_os_release_SOURCES = \
	tests/check-os-release.c

check_os_release_CFLAGS =		\
	$(BLKID_CFLAGS)		\
	$(CHECK_CFLAGS)		\
	$(AM_CFLAGS)

check_os_release_LDADD =	\
	libcbm.la	\
	src/libnica/libnica.la	\
	$(BLKID_LIBS)	\
	$(CHECK_LIBS)

@VALGRIND_CHECK_RULES@


VALGRIND_SUPPRESSIONS_FILES = \
	${abs_top_srcdir}/sgcheck.suppressions
