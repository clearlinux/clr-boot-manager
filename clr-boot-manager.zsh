#compdef clr-boot-manager
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

local ret=1 curcontext="$curcontext"
local context state state_descr line
local -A opt_args

_arguments -C \
           ':clr-boot-manager subcommand:->subcmd' \
  && ret=0

if [[ $state == subcmd ]]; then
   local -a subcmds; subcmds=(
     "version:Print the version and quit"
     "report-booted:Report the current kernel as successfully booted"
     "update:Perform post-update configuration of the system"
     "set-timeout:Set the timeout to be used by the bootloader"
     "get-timeout:Get the timeout to be used by the bootloader"
     "set-kernel:Configure kernel to be used at next boot"
     "list-kernels:Display currently selectable kernels to boot"
   )
   _describe -t subcmds 'clr-boot-manager sub-commands' subcmds && ret=0
fi

return ret
