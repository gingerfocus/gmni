.POSIX:
.SUFFIXES:
OUTDIR=.build
VERSION=0.0.0
include $(OUTDIR)/config.mk
include $(OUTDIR)/cppcache

gmni: $(gmni_objects)
	@printf 'CCLD\t$@\n'
	@$(CC) $(LDFLAGS) -o $@ $(gmni_objects) $(LIBS)

gmnlm: $(gmnlm_objects)
	@printf 'CCLD\t$@\n'
	@$(CC) $(LDFLAGS) -o $@ $(gmnlm_objects) $(LIBS)

libgmni.a: $(libgmni.a_objects)
	@printf 'AR\t$@\n'
	@$(AR) -rcs $@ $(libgmni.a_objects)

doc/gmni.1: doc/gmni.scd
doc/gmnlm.1: doc/gmnlm.scd

libgmni.pc:
	@printf 'GEN\t$@\n'
	@printf 'prefix=%s\n' "$(PREFIX)" > $@
	@printf 'exec_prefix=$${prefix}\n' >> $@
	@printf 'includedir=$${prefix}/include\n' >> $@
	@printf 'libdir=$${prefix}/lib\n' >> $@
	@printf 'Name: libgmni\n' >> $@
	@printf 'Version: %s\n' "$(VERSION)" >> $@
	@printf 'Description: The gmni client library\n' >> $@
	@printf 'Requires: libssl libcrypto\n' >> $@
	@printf 'Cflags: -I$${includedir}/gmni\n' >> $@
	@printf 'Libs: -L$${libdir} -lgmni\n' >> $@

.SUFFIXES: .c .o .scd .1

.c.o:
	@printf 'CC\t$@\n'
	@touch $(OUTDIR)/cppcache
	@grep $< $(OUTDIR)/cppcache >/dev/null || \
		$(CPP) $(CFLAGS) -MM -MT $@ $< >> $(OUTDIR)/cppcache
	@$(CC) -c -fPIC $(CFLAGS) -o $@ $<

.scd.1:
	@printf 'SCDOC\t$@\n'
	@$(SCDOC) < $< > $@

docs: doc/gmni.1 doc/gmnlm.1

clean:
	@rm -f gmni gmnlm libgmni.a libgmni.pc doc/gmni.1 doc/gmnlm.1 $(gmnlm_objects) $(gmni_objects)

distclean: clean
	@rm -rf "$(OUTDIR)"

install: all
	mkdir -p $(BINDIR)
	mkdir -p $(MANDIR)/man1
	install -Dm755 gmni $(BINDIR)/gmni
	install -Dm755 gmnlm $(BINDIR)/gmnlm
	install -Dm755 libgmni.a $(LIBDIR)/libgmni.a
	install -Dm644 include/gmni/gmni.h $(INCLUDEDIR)/gmni/gmni.h
	install -Dm644 include/gmni/tofu.h $(INCLUDEDIR)/gmni/tofu.h
	install -Dm644 include/gmni/url.h $(INCLUDEDIR)/gmni/url.h
	install -Dm644 libgmni.pc $(LIBDIR)/pkgconfig
	install -Dm644 doc/gmni.1 $(MANDIR)/man1/gmni.1
	install -Dm644 doc/gmnlm.1 $(MANDIR)/man1/gmnlm.1

.PHONY: clean distclean docs install
