# This is a makefile for locale management

APP		:= whois2
LOCALES := ru
POFILES := $(addsuffix /LC_MESSAGES/$(APP).po,$(addprefix locale/,$(LOCALES)))
MOFILES := $(addsuffix .mo,$(basename $(POFILES)))

help:
	@echo "================================="
	@echo "       Actions to perform        "
	@echo "================================="
	@echo "make pot: regenerate POT file"
	@echo "make pofiles: update pofiles"
	@echo "make mofiles: compile pofiles"


pot: locale/$(APP).pot

init:
	for locale in $(LOCALES); do mkdir -p "locale/$$locale/LC_MESSAGES"; done

pofiles: $(POFILES)
mofiles: $(MOFILES)

locale/%/LC_MESSAGES/$(APP).po: locale/$(APP).pot
	test -f $@ && msgmerge -U $@ $< || msginit -i $< -o $@ -l $* --no-translator

locale/%/LC_MESSAGES/$(APP).mo: locale/%/LC_MESSAGES/$(APP).po
	msgfmt -o $@ $<

locale/$(APP).pot: $(wildcard whois2/*.py) $(wildcard scripts/*)
	xgettext --language=python $^ -d $(APP) -p locale && mv locale/$(APP).po locale/$(APP).pot
