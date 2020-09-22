.POSIX:
.SUFFIXES:
OUTDIR=.build
include $(OUTDIR)/config.mk
include $(OUTDIR)/cppcache

gmni: $(gmni_objects)
	@printf 'CCLD\t$@\n'
	@$(CC) $(LDFLAGS) -o $@ $(gmni_objects) $(LIBS)

gmnlm: $(gmnlm_objects)
	@printf 'CCLD\t$@\n'
	@$(CC) $(LDFLAGS) -o $@ $(gmnlm_objects) $(LIBS)

doc/gmni.1: doc/gmni.scd
doc/gmnlm.1: doc/gmnlm.scd

.SUFFIXES: .c .o .scd .1

.c.o:
	@printf 'CC\t$@\n'
	@touch $(OUTDIR)/cppcache
	@grep $< $(OUTDIR)/cppcache >/dev/null || \
		$(CPP) $(CFLAGS) -MM -MT $@ $< >> $(OUTDIR)/cppcache
	@$(CC) -c $(CFLAGS) -o $@ $<

.scd.1:
	@printf 'SCDOC\t$@\n'
	@$(SCDOC) < $< > $@

docs: doc/gmni.1 doc/gmnlm.1

clean:
	@rm -f gmni doc/gmni.1 doc/gmnlm.1 $(gmnlm_objects) $(gmni_objects)

distclean: clean
	@rm -rf "$(OUTDIR)"

install: all
	mkdir -p $(BINDIR)
	mkdir -p $(MANDIR)/man1
	install -Dm755 gmni $(BINDIR)/gmni
	install -Dm755 gmnlm $(BINDIR)/gmnlm
	install -Dm644 doc/gmni.1 $(MANDIR)/man1/gmni.1
	install -Dm644 doc/gmnlm.1 $(MANDIR)/man1/gmnlm.1

.PHONY: clean distclean docs install
