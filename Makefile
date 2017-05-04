CFLAGS      = -Wall -Wextra -std=gnu99 -ggdb3 -O0
CPPFLAGS    = $(shell pkg-config --cflags glib-2.0,gio-2.0,libprocps,libxml-2.0)
LDLIBS      = $(shell pkg-config --libs glib-2.0,gio-2.0,libprocps,libxml-2.0)

all: dbus-map

dbus-map: dbus-map.o polkitagent.o actions.o util.o probes.o introspect.o

clean:
	rm -f dbus-map core *.o



test: dbus-map
	sudo -u nobody ./dbus-map --dump-methods --dump-properties --enable-probes --null-agent --timeout 1000
