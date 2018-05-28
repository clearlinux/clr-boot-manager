#!/bin/bash
#
# This file is part of clr-boot-manager.
#
# Copyright © 2017 Ikey Doherty
#
# clr-boot-manager is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1
# of the License, or (at your option) any later version.
#
set -e

testRoot=`pwd`
suppressions="$testRoot/sgcheck.suppressions"
coverDir="$testRoot/outCoverage"

# Nuke any existing builds
function nuke_build() {
    if [[ -d "build" ]]; then
        rm -rf "build"
    fi
}

# Just perform a single build
function build_one() {
    meson build --buildtype debugoptimized -Db_coverage=true --prefix=/usr --sysconfdir=/etc --datadir=/usr/share -Dwith-systemd-system-unit-dir=/lib/systemd/system $*
    ninja -C build
}

# Do a check with the various valgrind tools
function check_valgrind() {
    local valgrindArgs="valgrind --suppressions=\"$suppressions\" --error-exitcode=1"

    # Memory test
    meson test -C build --print-errorlogs --logbase=memcheck --wrap="$valgrindArgs --tool=memcheck --leak-check=full --show-reachable=no"
    meson test -C build --print-errorlogs --logbase=helgrind --wrap="$valgrindArgs --tool=helgrind"
    meson test -C build --print-errorlogs --logbase=drd --wrap="$valgrindArgs --tool=drd"
    # meson test -C build --logbase=sgcheck --wrap="$valgrindArgs --tool=exp-sgcheck"
}

# Do a "normal" test suite check
function check_normal() {
    meson test -C build --print-errorlogs
}

# Store the coverage report. If we have one, merge the new report. Finally,
# strip any unneeded noise from the report, to prepare it for upload
function stash_coverage() {
    ninja -C build coverage-html
    local coverageFile="$coverDir/coverage.info"
    local sampleFile="./build/meson-logs/coverage.info"

    if [[ ! -d "$coverDir" ]]; then
        mkdir "$coverDir"
    fi

    # Does this guy exist?
    if [[ ! -e "$coverageFile" ]]; then
        cp -v "$sampleFile" "$coverageFile"
    else
        # Merge them!
        lcov -a "$coverageFile" -a "$sampleFile" -o "${coverageFile}.tmp"

        # Stick this guy back as the main coverage file now
        mv "${coverageFile}.tmp" "$coverageFile"
    fi

    # Ensure we remove any unnecessary junk now
    lcov --remove "$coverageFile" 'tests/*' '/usr/*' --output-file "$coverageFile"
}

# Let's do our stock configuration first
echo "Performing stock configuration build"
nuke_build
build_one
check_normal
check_valgrind

# Stash the coverage as we'll want this guy later
stash_coverage

# Now let's do a non-stock build, i.e. one like Solus
echo "Performing non-stock configuration build"
nuke_build
build_one -Dwith-bootloader=systemd-boot --libdir=/usr/lib64
check_normal
check_valgrind

# Now merge the coverage with the last run
stash_coverage

# All succeeded, travis after_success will upload this
