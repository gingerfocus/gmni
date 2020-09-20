.POSIX:
.SUFFIXES:
OUTDIR=.build
include $(OUTDIR)/config.mk
include $(OUTDIR)/cppcache

gmni: $(gmni_objects)
	@printf 'CCLD\t$@\n'
	@$(CC) $(LDFLAGS) $(LIBS) -o $@ $(gmni_objects)

doc/gmni.1: doc/gmni.scd

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

docs: doc/gmni.1

clean:
	@rm -f gmni doc/gmni.1

distclean: clean
	@rm -rf "$(OUTDIR)"

.PHONY: clean distclean docs
