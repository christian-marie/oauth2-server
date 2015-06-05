SOURCES=$(shell find src lib test -name '*.hs' -type f)

HOTHASKTAGS=$(shell which hothasktags 2>/dev/null)
CTAGS=$(if $(HOTHASKTAGS),$(HOTHASKTAGS),/bin/false)

STYLISHHASKELL=$(shell which stylish-haskell 2>/dev/null)
STYLISH=$(if $(STYLISHHASKELL),$(STYLISHHASKELL),/bin/false)

all: format tags

.PHONY: all test clean

lint: $(SOURCES)
	for i in $^; do hlint $$i; done

format: .stylish-haskell.yaml $(SOURCES)
	$(STYLISH) -c $< -i $(filter-out $<,$^)

tags: $(SOURCES)
	@if [ "$(HOTHASKTAGS)" ] ; then /bin/echo -e "CTAGS\ttags" ; fi
	@$(CTAGS) $^ > tags $(REDIRECT)

clean:
	@/bin/echo -e "CLEAN"
	@cabal clean >/dev/null
	@rm -f tags

test:
	@/bin/echo -e "TEST"
	cabal test

build:
	cabal build

