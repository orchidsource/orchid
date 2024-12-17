# Cycc/Cympile - Shared Build Scripts for Make
# Copyright (C) 2013-2020  Jay Freeman (saurik)

# Zero Clause BSD license {{{
#
# Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# }}}


checks_ := $(subst $(space),$(comma),$(strip $(checks)))
checks = $(checks_),$(subst $(space),$(comma),$(checks/./$<))

# XXX: this is not a very accurate filter expression
filter := 
filter += source/.*\.[ch]pp
filter := (^|/)($(subst $(space),|,$(patsubst %,%,($(strip $(filter))))))$$

.PHONY: printenv
printenv:
	printenv

# XXX: $(error $(shell echo $(patsubst $(output)/./%,%,$(source)) | tr ' ' $$'\n' | grep -F '/./'))
object := $(foreach _,$(sort $(source)),$(_).o)

code = $(patsubst @/%,$(output)/$(arch)/%,$(header)) $(sysroot)

# XXX: replace cflags with cflags/ once I fix pwd to not begin with ./
# in this model, cflags would be something controlled only by the user
flags_ = $(if $(filter ./,$(1)),,$(call flags_,$(dir $(patsubst %/,%,$(1)))) $(cflags/$(1)))
flags- = $(call flags_,$(patsubst ./$(output)/%,%,$(patsubst ./$(output)/$(arch)/%,./$(output)/%,./$(dir $<))))
flags = $(filter-out $(dflags/./$<),$(qflags)) $(patsubst -I@/%,-I$(output)/$(arch)/%,$(filter -I%,$(cflags/./$<) $(flags-) $(cflags)) $(filter-out -I%,$(cflags) $(flags-) $(cflags/./$<)))
flags += $(if $(filter $(output)/%,$<),-D__FILE__='"$(patsubst $(output)/%,%,$<)"' -Wno-builtin-macro-redefined)

define compile
$(job)@LANG=C sed -e '1{x;s!.*!#line 1 "$<"!;p;x;};$(chacks/./$<)' $< | $(prefix) $($(1)) $(more/$(arch)) -MD -MP -c -o $@ $(3) $(flags) $(xflags) -iquote$(dir $<) -x $(2) -
endef

.PHONY: chacks
chacks:
	@{ $(foreach v,$(filter chacks/%,$(.VARIABLES)),echo 'diff $(v) += $($(v))'; sed -e '$($(v))' $(patsubst chacks/%,%,$(v)) | diff -u $(patsubst chacks/%,%,$(v)) - && echo $(v);)true; } | colordiff

$(output)/%.S.o: $$(specific) $$(folder).S $$(code)
	$(specific)
	@mkdir -p $(dir $@)
	@echo [CC] $(target)/$(arch) $<
	$(call compile,cc,assembler-with-cpp,)

$(output)/%.c.o: $$(specific) $$(folder).c $$(code)
	$(specific)
	@mkdir -p $(dir $@)
	@echo [CC] $(target)/$(arch) $<
	$(call compile,cc,c,)

$(output)/%.m.o: $$(specific) $$(folder).m $$(code)
	$(specific)
	@mkdir -p $(dir $@)
	@echo [CC] $(target)/$(arch) $<
	$(call compile,cc,objective-c,-fobjc-arc)

$(output)/%.mm.o: $$(specific) $$(folder).mm $$(code)
	$(specific)
	@mkdir -p $(dir $@)
	@echo [CC] $(target)/$(arch) $<
	$(call compile,cxx,objective-c++,-std=gnu++20 -fobjc-arc)

$(output)/%.cc.o: $$(specific) $$(folder).cc $$(code)
	$(specific)
	@mkdir -p $(dir $@)
	@echo [CC] $(target)/$(arch) $<
	$(call compile,cxx,c++,-std=c++20)

$(output)/%.c++.o: $$(specific) $$(folder).c++ $$(code)
	$(specific)
	@mkdir -p $(dir $@)
	@echo [CC] $(target)/$(arch) $<
	$(call compile,cxx,c++,-std=c++20)

$(output)/%.cpp.o: $$(specific) $$(folder).cpp $$(code)
	$(specific)
	@mkdir -p $(dir $@)
ifeq ($(filter notidy,$(debug)),)
	@if [[ $< =~ $(filter) && ! $< =~ .*/(base58|lwip|monitor)\.cpp ]]; then \
	    echo [CT] $(target)/$(arch) $<; \
	    $(tidy) $< --quiet --warnings-as-errors='*' --header-filter='$(filter)' --config='{Checks: "$(checks)", CheckOptions: [$(foreach v,$(filter checks/%,$(.VARIABLES)),{key: "$(patsubst checks/%,%,$(v))", value: $($(v))}$(comma) )]}' -- \
	        $(wordlist 2,$(words $(cxx)),$(cxx)) $(more/$(arch)) -std=c++2b -Wconversion -Wno-sign-conversion $(flags) $(xflags); \
	fi
endif
	@echo [CC] $(target)/$(arch) $<
	$(call compile,cxx,c++,-std=c++2b)

$(output)/%.rc.o: $$(specific) $$(folder).rc $$(code)
	$(specific)
	@mkdir -p $(dir $@)
	@echo [RC] $(target)/$(arch) $<
	$(job)@$(prefix) $(windres/$(arch)) -o $@ $< $(filter -I%,$(flags) $(xflags))

# XXX: pkg-config has an old embedded version of glib which no longer compiles
# https://gitlab.freedesktop.org/pkg-config/pkg-config/-/issues/81
# https://github.com/bazelbuild/rules_foreign_cc/issues/1065
# https://github.com/bazelbuild/rules_foreign_cc/issues/1200
# https://lists.freedesktop.org/archives/pkg-config/2024-May/001122.html
$(output)/%/pkg-config/Makefile: env/pkg-config/configure
	@mkdir -p $(dir $@)
	cd $(dir $@) && CFLAGS="-Wno-int-conversion" $(CURDIR)/$< --enable-static --prefix=$(CURDIR)/$(output)/$*/usr --with-internal-glib

$(output)/%/usr/bin/pkg-config: $(output)/%/pkg-config/Makefile
	$(MAKE) -C $(dir $<) install

export ENV_CURDIR := $(CURDIR)
export ENV_OUTPUT := $(output)

define _
$(shell env/cmake.sh $(1) $(output) '$(CURDIR)' '$(cmake) $(meson/$(1))' '$(ar/$(1))' '$(strip/$(1))' '$(windres/$(1))' '$(cc) $(more/$(1))' '$(cxx) $(more/$(1))' '$(objc) $(more/$(1))' '$(qflags)' '$(wflags)' '$(xflags)' '$(mflags)')
$(shell env/meson.sh $(1) $(output) '$(CURDIR)' '$(meson) $(meson/$(1))' '$(ar/$(1))' '$(strip/$(1))' '$(windres/$(1))' '$(cc) $(more/$(1))' '$(cxx) $(more/$(1))' '$(objc) $(more/$(1))' '$(qflags)' '$(wflags)' '$(xflags)' '$(mflags)')
endef
$(each)

%/configure: %/configure.ac $$(call head,$$(dir $$@))
	cd $(dir $@) && git clean -fxd .
	@# XXX: https://gitlab.freedesktop.org/pkg-config/pkg-config/-/issues/55
	@sed -i -e 's/^m4_copy(/m4_copy_force(/' $(dir $@)/glib/m4macros/glib-gettext.m4 || true
	env/autogen.sh $(dir $@) $(a_$(notdir $(patsubst %/configure.ac,%,$<)))

$(output)/%/Makefile: $$(specific) $$(folder)/configure $(sysroot) $$(call head,$$(folder)) $(output)/$$(arch)/usr/bin/pkg-config
	$(specific)
	@rm -rf $(dir $@)
	@mkdir -p $(dir $@)
	cd $(dir $@) && $(unshare) $(CURDIR)/$< --host=$(host/$(arch)) --prefix=$(CURDIR)/$(output)/$(arch)/usr \
	    CC="$(cc) $(more/$(arch))" CFLAGS="$(qflags)" CXX="$(cxx) $(more/$(arch))" CXXFLAGS="$(qflags) $(xflags)" \
	    RANLIB="$(ranlib/$(arch))" AR="$(ar/$(arch))" PKG_CONFIG="$(CURDIR)/env/pkg-config.sh" ENV_ARCH="$(arch)" \
	    CPPFLAGS="$(patsubst -I@/%,-I$(CURDIR)/$(output)/$(arch)/%,$(p_$(notdir $(patsubst %/configure,%,$<))))" \
	    LDFLAGS="$(wflags) $(patsubst -L@/%,-L$(CURDIR)/$(output)/$(arch)/%,$(l_$(subst -,_,$(notdir $(patsubst %/configure,%,$<)))))" \
	    --enable-static --disable-shared $(subst =@/,=$(CURDIR)/$(output)/$(arch)/,$(w_$(subst -,_,$(notdir $(patsubst %/configure,%,$<)))))
	cd $(dir $@); $(m_$(subst -,_,$(notdir $(patsubst %/configure,%,$<))))

$(output)/%/cmake/Makefile: $$(specific) $$(folder)/CMakeLists.txt $(output)/$$(arch)/cmake.txt $(sysroot) $$(call head,$$(folder))
	$(specific)
	@rm -rf $(dir $@)
	@mkdir -p $(dir $@)
	cmake -S$(dir $<) --toolchain $(CURDIR)/$(output)/$(arch)/cmake.txt -B$(dir $@) -DCMAKE_BUILD_TYPE=Release

$(output)/%/build.ninja: $$(specific) $$(folder)/meson.build $(output)/$$(arch)/meson.txt $(sysroot) $$(call head,$$(folder)) $(output)/$$(arch)/usr/bin/pkg-config
	$(specific)
	@rm -rf $(dir $@)
	@mkdir -p $(dir $@)
	cd $(dir $<) && ENV_ARCH="$(arch)" $(unshare) meson setup --cross-file $(CURDIR)/$(output)/$(arch)/meson.txt $(CURDIR)/$(dir $@) \
	    -Ddefault_library=static $(w_$(subst -,_,$(notdir $(patsubst %/meson.build,%,$<))))
	cd $(dir $@); $(m_$(subst -,_,$(notdir $(patsubst %/meson.build,%,$<))))

rust := PATH=$${PATH}:~/.cargo/bin

rustc := 1.82.0

$(output)/rustup-install-%:
	$(rust) rustup install $*
	@touch $@
	
$(output)/rustup-target-$(rustc)-%: $(output)/rustup-install-$(rustc)
	$(rust) rustup target add $* --toolchain $(rustc)
	@touch $@

ifneq ($(uname-o),Cygwin)
export RUSTC_WRAPPER=$(CURDIR)/env/rustc-wrapper
endif

$(output)/%/librust.a: $$(specific) $$(folder)/Cargo.toml $(output)/rustup-target-$(rustc)-$$(triple/$$(arch)) $(sysroot) $$(call head,$$(folder)) $(output)/$$(arch)/usr/bin/pkg-config
	$(specific)
	@mkdir -p $(dir $@)
	
	@# rust/cargo/cc incorrectly models --target $host as building for the host
	@# this bug is being tracked https://github.com/rust-lang/cargo/issues/8147
	@$(eval ccrs := $(if $(filter $(triple/$(arch)),$(shell $(rust) rustup show | sed -e '/^Default host: /!d;s///')),HOST,TARGET))
	@# or if using rustc: rustc --version --verbose | sed -e '/^host: /!d;s///'
	
	@# https://github.com/buildroot/buildroot/commit/4b2be770b8a853a7dd97b5788d837f0d84923fa1
	cd $(folder) && ENV_RUST=$(notdir $(folder)) RUST_BACKTRACE=1 $(rust):$(dir $(word 1,$(cc))) \
	    $(ccrs)_CC='$(cc) $(more/$(arch))' $(ccrs)_CFLAGS='$(qflags)' \
	    $(ccrs)_CXX='$(cxx) $(more/$(arch))' $(ccrs)_CXXFLAGS='$(qflags) $(xflags)' \
	    $(ccrs)_AR='$(ar/$(arch))' \
	    PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG="$(CURDIR)/env/pkg-config.sh" ENV_ARCH="$(arch)" \
	    CARGO_HOME='$(call path,$(CURDIR)/$(output)/cargo)' CARGO_INCREMENTAL=0 \
	    __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly CARGO_TARGET_APPLIES_TO_HOST=false \
	    CARGO_TARGET_$(subst -,_,$(call uc,$(triple/$(arch))))_LINKER='$(firstword $(cc))' \
	    CARGO_TARGET_$(subst -,_,$(call uc,$(triple/$(arch))))_RUSTFLAGS='$(foreach arg,$(wordlist 2,$(words $(cc)),$(cc)) $(more/$(arch)) $(wflags),-C link-arg=$(arg)) $(rflags)' \
	    cargo +$(rustc) build --verbose --lib --release --features "$(features/$(folder))" \
	        --target $(triple/$(arch)) -Z target-applies-to-host \
	        --target-dir $(call path,$(CURDIR)/$(output)/$(arch)/$(folder))
	cp -f $(output)/$(arch)/$(folder)/$(triple/$(arch))/release/lib$(subst -,_,$(notdir $(folder))).a $@

.PHONY: clean
clean:
	git clean -fXd

define _
-include $(patsubst %.o,$(output)/$(1)/%.d,$(object))
endef
$(each)

define _
$(output)/%/$(1)_.a: $(patsubst %,$(output)/$$(percent)/%,$(filter $(1)%.o,$(object)))
	@rm -f $$@
	@echo [AR] $$@
	@$$(ar/$$*) -rcs $$@ $$^
object := $(filter-out $(1)%.o,$(object))
linked += $(1)_.a
endef
$(foreach archive,$(archive),$(eval $(call _,$(archive))))

define _
object := $$(patsubst $(1).o,$(1)-.o,$$(object))
$$(output)/%/$(1)-.o: $$(output)/%/$(1).o
	$$(objcopy) $(2) $$< $$@
endef
$(foreach oflags,$(filter oflags/%,$(.VARIABLES)),$(eval $(call _,$(patsubst oflags/%,%,$(oflags)),$($(oflags)))))
