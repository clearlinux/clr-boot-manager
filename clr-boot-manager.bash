#!/bin/bash
# -----------------------------------------------------------------------
#   Software Updater - autocompletion script
#
#   Author: Lucius Hu - http://github.com/lebensterben
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, version 2 or later of the License.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------

_clr-boot-manager()
{
  if [ "${#COMP_WORDS[@]}" != "2" ]; then
    return
  fi

  COMPREPLY=($(compgen -W "version report-booted help update set-timeout get-timeout set-kernel list-kernels" "${COMP_WORDS[1]}"))
}

complete -F _clr-boot-manager clr-boot-manager
