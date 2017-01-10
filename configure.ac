AC_INIT([clr-boot-manager], 1.1.0, [michael.i.doherty@intel.com], [clr-boot-manager], [michael.i.doherty@intel.com])
AM_INIT_AUTOMAKE([-Wno-portability no-dist-gzip dist-xz foreign subdir-objects])
AC_PROG_CC
AC_PROG_CC_STDC
AC_CONFIG_HEADERS([config.h])
AC_PREFIX_DEFAULT(/usr/local)
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([m4])
AX_VALGRIND_CHECK
LT_INIT

# Unit tests
PKG_CHECK_MODULES([CHECK], [check >= 0.9])
PKG_CHECK_MODULES([BLKID], [blkid])

have_coverage=no
AC_ARG_ENABLE(coverage, AS_HELP_STRING([--enable-coverage], [enable test coverage]))
if test "x$enable_coverage" = "xyes" ; then
        AC_CHECK_PROG(lcov_found, [lcov], [yes], [no])
        if test "x$lcov_found" = xno ; then
                AC_MSG_ERROR([*** lcov support requested but the program was not found])
        else
                lcov_version_major="`lcov --version | cut -d ' ' -f 4 | cut -d '.' -f 1`"
                lcov_version_minor="`lcov --version | cut -d ' ' -f 4 | cut -d '.' -f 2`"
                if test "$lcov_version_major" -eq 1 -a "$lcov_version_minor" -lt 10; then
                        AC_MSG_ERROR([*** lcov version is too old. 1.10 required])
                else
			have_coverage=yes
			AC_DEFINE([COVERAGE], [1], [Coverage enabled])
                fi
        fi
fi
AM_CONDITIONAL([COVERAGE], [test "$have_coverage" = "yes"])

# Enable compat scripts? Enabled by default
AC_ARG_ENABLE(compat-scripts, AS_HELP_STRING([--enable-compat-scripts], [enable compat scripts]))
use_compat_scripts=yes
if test x$enable_compat_scripts = "xno"; then
        use_compat_scripts="no"
else
        use_compat_scripts="yes"
fi

AM_CONDITIONAL([COMPAT_SCRIPTS], [test "$use_compat_scripts" = "yes"])


AC_ARG_WITH([bootloader], AS_HELP_STRING([--with-bootloader=BOOTLOADER],
        [the bootloader to use]), [bootloader=${withval}],
        [bootloader="auto"])

if test x$bootloader = "xauto"; then
        AC_MSG_CHECKING([whether an EFI bootloader is available])
        if test -e "/usr/lib/systemd/boot/efi"; then
                bootloader="systemd-boot"
        elif test -e "/usr/lib/goofiboot"; then
                bootloader="goofiboot"
        # use newer goofiboot, may be dual installed
        elif test -e "/usr/lib/gummiboot"; then
                bootloader="gummiboot"
        else
                AC_MSG_WARN([Cannot find a valid EFI bootloader, defaulting to systemd-boot])
                bootloader="systemd-boot"
        fi
        AC_MSG_RESULT([$bootloader])
fi

# Now test the option
if test x$bootloader = "xsystemd-boot"; then
        have_systemdboot="yes"
        AC_DEFINE([HAVE_SYSTEMD_BOOT], [1], [Using systemd-boot])
elif test x$bootloader = "xgummiboot"; then
        have_gummiboot="yes"
        AC_DEFINE([HAVE_GUMMIBOOT], [1], [Using gummiboot])
elif test x$bootloader = "xgoofiboot"; then
        have_goofiboot="yes"
        AC_DEFINE([HAVE_GOOFIBOOT], [1], [Using goofiboot])
else
        AC_MSG_ERROR([Unknown bootloader, use: systemd-boot, gummiboot, or goofiboot])
fi

AM_CONDITIONAL([HAVE_SYSTEMD_BOOT], [test x$have_systemdboot = "xyes"])
AM_CONDITIONAL([HAVE_GUMMIBOOT], [test x$have_gummiboot = "xyes"])
AM_CONDITIONAL([HAVE_GOOFIBOOT], [test x$have_goofiboot = "xyes"])

AC_ARG_WITH([kernel-dir], AS_HELP_STRING([--with-kernel-dir],
        [the kernel directory to use]), [kerneldir=${withval}],
        [kerneldir="/usr/lib/kernel"])

AC_SUBST(kerneldir)
AC_DEFINE_UNQUOTED(KERNEL_DIRECTORY, "$kerneldir",
                   [The location of kernels in this OS configuration])

AC_ARG_WITH([kernel-modules-dir], AS_HELP_STRING([--with-kernel-modules-dir],
        [the kernel modules directory to use]), [kernelmodulesdir=${withval}],
        [kernelmodulesdir="/usr/lib/modules"])

AC_SUBST(kernelmodulesdir)
AC_DEFINE_UNQUOTED(KERNEL_MODULES_DIRECTORY, "$kernelmodulesdir",
                   [The location of kernel modules in this OS configuration])

AC_ARG_WITH([kernel-namespace], AS_HELP_STRING([--with-kernel-namespace],
        [the kernel path namespace to use]), [kernelnamespace=${withval}],
        [kernelnamespace="org.clearlinux"])

AC_SUBST(kernelnamespace)
AC_DEFINE_UNQUOTED(KERNEL_NAMESPACE, "$kernelnamespace",
                   [The path namespace for kernels in this OS configuration])


AC_ARG_WITH([boot-dir], AS_HELP_STRING([--with-boot-dir],
        [the path to the normalised ESP mount]), [bootdir=${withval}],
        [bootdir="/boot"])

AC_SUBST(bootdir)
AC_DEFINE_UNQUOTED(BOOT_DIRECTORY, "$bootdir",
                   [The normalised path to the boot/ESP mount])

# The vendor prefix used for files created by clr-boot-manager within bootdir
AC_ARG_WITH([vendor-prefix], AS_HELP_STRING([--with-vendor-prefix],
        [the config file vendor prefix]), [vendorprefix=${withval}],
        [vendorprefix="generic-linux-os"])

AC_SUBST(vendorprefix)
AC_DEFINE_UNQUOTED(VENDOR_PREFIX, "$vendorprefix",
                   [The vendor prefix])

# The kernel configuration directory
AC_ARG_WITH([kernel-conf-dir], AS_HELP_STRING([--with-kernel-conf-dir],
        [the kernel configuration directory]), [kernelconfdir=${withval}],
        [kernelconfdir="/etc/kernel"])

AC_SUBST(kernelconfdir)
AC_DEFINE_UNQUOTED(KERNEL_CONF_DIRECTORY, "$kernelconfdir",
                   [The kernel configuration directory])


# Options
AC_ARG_WITH([systemdsystemunitdir], AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
	[path to systemd system service directory]), [path_systemdsystemunit=${withval}],
	[path_systemdsystemunit="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"])
SYSTEMD_SYSTEMUNITDIR="${path_systemdsystemunit}"
AC_SUBST(SYSTEMD_SYSTEMUNITDIR)
AM_CONDITIONAL(SYSTEMD, test -n "${path_systemdsystemunit}")

AC_CONFIG_FILES([Makefile])

AC_OUTPUT

AC_MSG_RESULT([
        clr-boot-manager $VERSION
        ========

        prefix:                 ${prefix}
        libdir:                 ${libdir}
        sysconfdir:             ${sysconfdir}
        exec_prefix:            ${exec_prefix}
        bindir:                 ${bindir}
        datarootdir:            ${datarootdir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}

        bootloader:             ${bootloader}
        kernel-dir:             ${kerneldir}
        kernel-modules-dir:     ${kernelmodulesdir}
        kernel-namespace:       ${kernelnamespace}
        kernel-conf-dir:        ${kernelconfdir}
        boot-dir:               ${bootdir}
        vendor-prefix:          ${vendorprefix}

        compatibility scripts:  ${use_compat_scripts}
])
