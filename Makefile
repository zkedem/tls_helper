.POSIX:

PROGRAMS = tls_client tls_server
LIBRARIES = tls_helper
LIBRARYPREFIX = lib
LIBRARYSUFFIX = .so
HELPSUFFIX = _help
CC = cc
CFLAGS = -Os -s
LDFLAGS = -lwolfssl -lbsddaemon
PREFIX = /usr
LIBDIR = $(PREFIX)/lib
BINDIR = $(PREFIX)/bin

build: libraries helptext
	for p in $(PROGRAMS); \
	do \
		$(CC) $(CFLAGS) "$$p".c "$$p"$(HELPSUFFIX).o -o $$p $(LDFLAGS) -L. `echo $(LIBRARIES) | tr " " "\n" | sed -E "s/(.*)/-l\1/g"`; \
	done

libraries:
	for l in $(LIBRARIES); \
	do \
		$(CC) $(CFLAGS) -shared -fPIC -o $(LIBRARYPREFIX)"$$l"$(LIBRARYSUFFIX) "$$l".c $(LDFLAGS); \
	done

helptext:
	for p in $(PROGRAMS); \
	do \
		{ \
			echo "unsigned char help[] = {"; \
			xxd -i < "$$p"$(HELPSUFFIX).txt; \
			echo ", 0x00};"; \
		} | $(CC) -c -o "$$p"$(HELPSUFFIX).o -xc -; \
	done

rebuild: clean build

clean:
	rm -f $(PROGRAMS)
	rm -f *.so
	rm -f *.o

install: install-libraries
	for p in $(PROGRAMS); \
	do \
		cp "$$p" $(BINDIR); \
	done

install-libraries:
	for l in $(LIBRARIES); \
	do \
		cp $(LIBRARYPREFIX)"$$l"$(LIBRARYSUFFIX) $(LIBDIR); \
	done

uninstall: uninstall-libraries
	for p in $(PROGRAMS); \
	do \
		rm -f $(BINDIR)"/$$p"; \
	done

uninstall-libraries:
	for l in $(LIBRARIES); \
	do \
		rm -f "$(LIBDIR)/$(LIBRARYPREFIX)$$l$(LIBRARYSUFFIX)"; \
	done
