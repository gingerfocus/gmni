.POSIX:
.SUFFIXES:
OUTDIR=.build
include $(OUTDIR)/config.mk
include $(OUTDIR)/cppcache

gmnic: $(gmnic_objects)
	@printf 'CCLD\t$@\n'
	@$(CC) $(LDFLAGS) $(LIBS) -o $@ $(gmnic_objects)

doc/gmnic.1: doc/gmnic.scd

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

docs: doc/gmnic.1

clean:
	@rm -f gmnic

distclean: clean
	@rm -rf "$(OUTDIR)"

.PHONY: clean distclean docs
