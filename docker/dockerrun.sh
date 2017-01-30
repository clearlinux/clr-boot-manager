#!/bin/bash
#
# This file is part of clr-boot-manager.
#
# Copyright © 2017 Intel Corporation
#
# clr-boot-manager is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1
# of the License, or (at your option) any later version.
#
mkdir -p /build
cd /build

if [[ ! -d /source ]]; then
    echo "Missing source tree!" >&2
    exit 1
fi

# Copy all the files across to prevent contaminating the bind mount
cp -Ra /source/. /build

die_fatal()
{
    exit 1
}

die_log_fatal()
{
    if [[ -e test-suite.log ]]; then
        cat test-suite.log
    else
        echo "test-suite.log is missing." >&2
    fi
    exit 1
}

./autogen.sh --enable-coverage || die_fatal

# Build error
make || die_fatal

# Test suite failure, print the log
make check || die_log_fatal

# tarbal issue, just die
make distcheck || die_fatal

# Actually checkable on host, but dump log anyway
make check-valgrind || die_log_fatal

# At this point, we can emit our current coverage to the tty
make coverage
