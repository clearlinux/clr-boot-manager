clr-boot-manager
----------------

[![Build Status](https://travis-ci.org/ikeydoherty/clr-boot-manager.svg?branch=master)](https://travis-ci.org/ikeydoherty/clr-boot-manager)
[![Coverage Status](https://coveralls.io/repos/github/ikeydoherty/clr-boot-manager/badge.png?branch=master)](https://coveralls.io/github/ikeydoherty/clr-boot-manager?branch=master)


clr-boot-manager  exists  to  enable the correct maintainence of vendor
kernels and appropriate garbage collection tactics over the  course  of
upgrades.   The  implementation  provides  the  means to enable correct
cohabitation on a shared boot directory, such as the EFI System  Partition
for UEFI-booting operating systems.

Special  care  is taken to ensure the ESP is handled gracefully, and in
the instance that it is not already mounted, then clr-boot-manager will
automatically  discover and mount it, and automatically unmount the ESP
again when it is complete.

Requirements
------------

clr-boot-manager is designed to operate solely with `GPT` disks, and
exclusively uses `PARTUUID`. Generated boot entries also contain the `PARTUUID`
in their `root=` command line, as part of a merge of the vendor provided
`cmdline` files for default options.

License
-------
LGPL-2.1

Copyright © 2016-2017 Intel Corporation
