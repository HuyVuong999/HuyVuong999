CFLAGS = -fomit-frame-pointer
CFLAGS += $(BRCM_WERROR_CFLAGS)
CFLAGS += -D_GNU_SOURCE -Wall -I./libnetfilter_queue/include -I./libnfnetlink/include
ifeq ($(strip $(BUILD_URLFILTER)), static)
CFLAGS += -DBUILD_STATIC
endif

LDFLAGS = -Wl,-L./libnfnetlink -L./libnetfilter_queue

LIBS = -lpthread -lnetfilter_queue -lnfnetlink

OBJS = packet.o packet_pool.o domain_tree.o filter.o main.o

all: debug

install: filterd
	install -m 755 filterd $(INSTALL_DIR)/bin
	$(STRIP) $(INSTALL_DIR)/bin/filterd

dynamic: all install

static: filterd.a

.c.o:
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $<

gen-libs:
	$(MAKE) -C libnfnetlink
	$(MAKE) -C libnetfilter_queue

filterd: gen-libs packet.o packet_pool.o domain_tree.o filter.o main.o
	$(CC) -o filterd packet.o packet_pool.o main.o domain_tree.o filter.o $(LDFLAGS) $(LIBS)

filterd.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

set-debug-flags:
	$(eval EXTRA_CFLAGS := -ggdb -O0 -DDEBUG)

set-release-flags:
    $(eval EXTRA_CFLAGS := -O2 -s)

release: set-release-flags filterd
	$(STRIP) filterd

debug: set-debug-flags filterd

clean:
	$(MAKE) -C libnfnetlink clean
	$(MAKE) -C libnetfilter_queue clean
	rm -f filterd *.o  filterd.a
