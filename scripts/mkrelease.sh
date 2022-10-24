#!/bin/bash
#
# This file is part of clr-boot-manager.
#
# Copyright © 2017 Ikey Doherty
# Copyright © 2020 Intel Corporation
#
# clr-boot-manager is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1
# of the License, or (at your option) any later version.
#

set -e

pkg="clr-boot-manager"
SIGN=0

print_help() {
    echo -e "mkrelease.sh [--help] [options]

mkrelease.sh executes all the required steps before cutting a new release(set
new version, creates bundled artifacts including vendored components, creates
the release tag etc).

Help Options:
    -h, --help		Show this help list

Options:
    -n, --new-version	The release's new version"
}

for curr in "$@"; do
    case $curr in
	"--new-version"|"-n")
	    version=$2
	    shift
	    shift
	    ;;
        "--sign"|"-s")
            SIGN=1
            shift
            ;;
	"--help"|"-h")
	    print_help;
	    exit 0;;
    esac
done

if [ "$version" == "" ]; then
    echo "No version provided, please use \"--new-version\" flag. Use --help for more information."
    exit 1
fi

echo "${version}" > VERSION
git commit -a -s -m "v${version} release"
git tag "v${version}"

git submodule init
git submodule update

./scripts/git-archive-all.sh --format tar --prefix ${pkg}-${version}/ \
			     --verbose -t "v${version}" ${pkg}-${version}.tar

xz -9 "${pkg}-${version}.tar"

# Automatically sign the tarball
if [ $SIGN -eq 1 ]; then
    gpg --armor --detach-sign "${pkg}-${version}.tar.xz"
    gpg --verify "${pkg}-${version}.tar.xz.asc"
fi
