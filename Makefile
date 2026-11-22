CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra
LDFLAGS  ?=
LIBS     := -lssl -lcrypto

PREFIX   ?= /usr/local
BINDIR   := $(PREFIX)/bin
UNITDIR  := /etc/systemd/system
CONFDIR  := /etc/applock

TARGET   := applock
SRC      := applock.c

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -d $(DESTDIR)$(CONFDIR)
	touch $(DESTDIR)$(CONFDIR)/config
	chmod 600 $(DESTDIR)$(CONFDIR)/config
	install -m 644 applock.service $(DESTDIR)$(UNITDIR)/applock.service

uninstall:
	-systemctl disable --now applock.service 2>/dev/null || true
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(UNITDIR)/applock.service
	@echo "Konfiguracja w $(CONFDIR) pozostawiona (usuń ręcznie, jeśli chcesz)."
