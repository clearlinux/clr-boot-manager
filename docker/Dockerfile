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

FROM clearlinux:latest
ADD dockerrun.sh /dockerrun.sh
RUN swupd update && swupd bundle-add c-basic dev-utils-dev

CMD ["/dockerrun.sh"]
