#!/bin/bash
set -e

top_srcdir="${1}"
top_builddir="${2}"
boot_dir="${3}"

BLOBFILE="${top_srcdir}/tests/data/blobfile"

if [[ -d "${top_builddir}/tests/dummy_install/" ]]; then
    rm -rf "${top_builddir}/tests/dummy_install/"
    mkdir -p "${top_builddir}/tests/dummy_install/"
    mkdir -p "${top_builddir}/tests/dummy_install/${boot_dir}"
fi

# where we "install" kernels in the test suite
if [[ ! -d "${top_builddir}/tests/dummy_install/usr/lib/kernel" ]]; then
    mkdir -p "${top_builddir}/tests/dummy_install/usr/lib/kernel"
fi

for kernel in "kvm.4.2.1-121" "kvm.4.2.3-124" "native.4.2.1-137" "native.4.2.3-138"; do
    kfile="${top_builddir}/tests/dummy_install/usr/lib/kernel/org.clearlinux.${kernel}";
    if [[ ! -e "${kfile}" ]]; then
        cp  "${BLOBFILE}" "${kfile}"
    fi
    spl=`echo ${kernel}|cut -d '-' -f 1`
    rel=`echo ${kernel}|cut -d '-' -f 2`
    letype=`echo ${spl}|cut -d . -f 1`
    leversion=`echo ${spl}|cut -d . -f 2,3,4`
    cmdfile="${top_builddir}/tests/dummy_install/usr/lib/kernel/cmdline-${leversion}-${rel}.${letype}"
    if [[ ! -e "${cmdfile}" ]]; then
        echo "THIS WOULD BE A CMDLINE FILE" > "${cmdfile}"
    fi
    kconfigfile="${top_builddir}/tests/dummy_install/usr/lib/kernel/config-${leversion}-${rel}.${letype}"
    if [[ ! -e "${kconfigfile}" ]]; then
        echo "THIS WOULD BE A KCONFIG FILE" > "${kconfigfile}"
    fi
    # Create faux module tree
    moduledir="${top_builddir}/tests/dummy_install/usr/lib/modules/${leversion}-${rel}"
    if [[ ! -d "${moduledir}" ]]; then
        mkdir -p "${moduledir}"
        mkdir -p "${moduledir}"/{build,source,extra,kernel,updates}
        mkdir -p "${moduledir}"/kernel/{arch,crypto,drivers,fs,lib,mm,net,sound}
        touch "${moduledir}"/kernel/{arch,crypto,drivers,fs,lib,mm,net,sound}/dummy.ko
    fi

done

# Install default files as seen for swupd in clear
ln -s "org.clearlinux.kvm.4.2.3-124"    "${top_builddir}/tests/dummy_install/usr/lib/kernel/default-kvm"
ln -s "org.clearlinux.native.4.2.3-138" "${top_builddir}/tests/dummy_install/usr/lib/kernel/default-native"

if [[ ! -d "${top_builddir}/tests/dummy_install/usr/bin" ]]; then
        mkdir -p "${top_builddir}/tests/dummy_install/usr/bin"
fi
if [[ ! -d "${top_builddir}/tests/dummy_install/usr/lib" ]]; then
        mkdir -p "${top_builddir}/tests/dummy_install/usr/lib"
fi

# Make bootloader files available during tests
if [[ -e /usr/bin/goofiboot ]]; then
        cp /usr/bin/goofiboot "${top_builddir}/tests/dummy_install/usr/bin/."
        cp -R /usr/lib/goofiboot "${top_builddir}/tests/dummy_install/usr/lib/."
fi
if [[ -e /usr/bin/gummiboot ]]; then
        cp /usr/bin/gummiboot "${top_builddir}/tests/dummy_install/usr/bin/."
        cp -R /usr/lib/gummiboot "${top_builddir}/tests/dummy_install/usr/lib/."
fi
if [[ -e /usr/bin/bootctl ]]; then
        cp /usr/bin/bootctl "${top_builddir}/tests/dummy_install/usr/bin/."
        mkdir -p "${top_builddir}/tests/dummy_install/usr/lib/systemd/boot/"
        cp -R /usr/lib/systemd/boot/efi "${top_builddir}/tests/dummy_install/usr/lib/systemd/boot"
fi
