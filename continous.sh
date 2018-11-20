#!/bin/bash
#
# This file is part of clr-boot-manager.
#
# Copyright © 2017-2018 Intel Corporation
#
# clr-boot-manager is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1
# of the License, or (at your option) any later version.
#

DIRN="$(basename $(pwd))"
PROJ_NAME="clr-boot-manager"
PROJ_CI_NAME="docker-ci-${PROJ_NAME}"

# Check docker is available
if ! type docker &>/dev/null; then
    echo "Please ensure docker is installed first"
    exit 1
fi

# Check docker is running
if ! docker version &>/dev/null; then
    echo "Docker is not running"
    exit 1
fi

# Check we're in the right directory
if [[ "${DIRN}" != "${PROJ_NAME}" ]]; then
    echo "Please run from the root ${PROJ_NAME} directory"
    exit 1
fi

# Check that docker-ci image is installed
if ! docker inspect "${PROJ_CI_NAME}" &>/dev/null; then
    echo "${PROJ_CI_NAME} not installed, building docker image.."
    echo "....Please wait, this may take some time."
    docker build -t "${PROJ_CI_NAME}" docker/ || exit 1
fi

# Build the current tree through bind mount within the docker image
echo "Beginning build of ${PROJ_NAME}..."
exec docker run -ti -v $(pwd):/source:ro --rm "${PROJ_CI_NAME}"
