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

git submodule init
git submodule update

VERSION="v1.5.4"
NAME="clr-boot-manager"
./scripts/git-archive-all.sh --format tar --prefix ${NAME}-${VERSION}/ --verbose -t HEAD ${NAME}-${VERSION}.tar
xz -9 "${NAME}-${VERSION}.tar"

# Automatically sign the tarball
gpg --armor --detach-sign "${NAME}-${VERSION}.tar.xz"
gpg --verify "${NAME}-${VERSION}.tar.xz.asc"               
