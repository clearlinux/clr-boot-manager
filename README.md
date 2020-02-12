clr-boot-manager
----------------

![](https://github.com/clearlinux/clr-boot-manager/workflows/CI/badge.svg)

clr-boot-manager exists to enable the correct maintenance of vendor kernels and appropriate garbage collection tactics over the course of upgrades. The implementation provides the means to enable correct cohabitation on a shared boot directory, such as the EFI System Partition for UEFI-booting operating systems.

Special care is taken to ensure the boot partition is handled gracefully, and in the instance that it is not already mounted, then clr-boot-manager will automatically discover and mount it, and automatically unmount the boot partition again when it is complete.

Most importantly, clr-boot-manager provides a simple mechanism to provide kernel updates, with the ability for users to rollback to an older kernel should the new update be problematic. This is achieved through the use of strict namespace policies, permanent source paths, and clr-boot-manager's own internal logic, without the need for "meta packages" or undue complexity on the distribution side.

Requirements
------------

clr-boot-manager is primarily designed to install the bootloader, kernel, initrd and accompanying metadata files for GPT disks using UEFI, however it does contain fallback support for legacy bootloaders such as GRUB2 to allow all users to benefit from automated kernel management when MBR partition tables are used.

clr-boot-manager should be the only tool responsible within the OS for generating boot entries, and will automatically incorporate the correct `root=` portions.

Kernel Integration
------------------

The way that a kernel is packaged changes significantly with clr-boot-manager. First and foremost, no files shall be shipped in `/boot`. The distribution should choose a namespace to identify their system in dual-boot situations, i.e:

    org.someproject

All paths known to CBM must have follow a specific format and encoding, whereby
the version, release number, and *type* are encoded:

    /usr/lib/kernel
     -> config-4.9.17-9.lts
     -> org.someproject.lts.4.9.17-9
     -> System.map-4.9.17-9.lts
     -> cmdline-4.9.17-9.lts
     -> initrd-org.someproject.lts.4.9.17-9 (Optional)
    /usr/src/linux-headers-4.9.17-9.lts
    /usr/lib/modules/4.9.17-9.lts

The directories can be altered via the `./configure` options. See `./configure --help` for further details.

Additionally, each kernel shall be compiled with the versioning information built
in, which can be achieved by doing something similar to this in the build spec:

    extraVersion="-${release}.lts"
    sed -e "s/EXTRAVERSION =.*/EXTRAVERSION = $extraVersion/" -i Makefile

This results in an easily identifiable `uname` which CBM can use to manage kernels:


    $ uname -a
    Linux some-host 4.9.17-9.lts #1 SMP Wed Mar 22 16:02:52 UTC 2017 x86_64 GNU/Linux

The `initrd` file should be shipped with the kernel package itself, built for a generic target. This minimises the errors that can happen when having a non reproducible command. Users may override the initrd by providing the same filename within `/etc/kernel`.

All of the above paths should be marked as resident/permanent in the software deployment mechanism as they will be automatically destroyed when clr-boot-manager performs the garbage collection cycle. Note that each "type" of kernel is up to the distribution to define, however it should be alphabetical only with no dots or hyphens.

The next "default" kernel (i.e. tip for a given series) is defined with the `symlink-$(type)` notation, and allows clr-boot-manager to know that a kernel is not yet up to date. No version comparison is performed, ensuring that the symlink is always the source of information:

`/usr/lib/kernel/default-lts: symbolic link to org.someproject.lts.4.9.17-9`

The "post install" step for a kernel shall call `clr-boot-manager update` to push the new configuration & updates to disk. This can be called multiple times, as clr-boot-manager will only update exactly what needs to be updated, saving unnecessary writes to the ESP or `/boot` partition.

Supported Filesystems/Partition Table
-------------------------------------
The clr-boot-manager supports the following filesystems combination:

UEFI | Filesystem | Backend
-----| -----------| -------
no | ext[2-4] | extlinux
no | vfat | syslinux
yes | vfat | systemd-boot

License
-------
LGPL-2.1

Copyright © 2016-2020 Intel Corporation
