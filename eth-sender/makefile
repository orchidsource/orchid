# Orchid - WebRTC P2P VPN Market (on Ethereum)
# Copyright (C) 2017-2020  The Orchid Authors

# GNU Affero General Public License, Version 3 {{{ */
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# }}}


args := 

include env/target.mk

.PHONY: all
all: $(output)/$(machine)/cj$(exe)

.PHONY: test
test: $(output)/$(machine)/cj$(exe)
	$< $(args)

source += $(wildcard $(pwd)/source/*.cpp)
cflags += -I$(pwd)/source

# XXX: this literally crashes clang-tidy and I haven't filed the bug
checks/$(pwd)/source/main.cpp += -bugprone-unchecked-optional-access

$(call include,lib/target.mk)

linked += $(pwd)/riscy/librust.a
cflags += -I$(pwd)/riscy
$(call depend,$(pwd)/riscy/librust.a,$(pwd)/riscy/riscy.rs)

include env/output.mk

$(output)/%/cj$(exe): $(patsubst %,$(output)/$$*/%,$(object) $(linked))
	@mkdir -p $(dir $@)
	@echo [LD] $@
	@$(cxx) $(more/$*) $(wflags) -o $@ $^ $(lflags)
	@ls -la $@
