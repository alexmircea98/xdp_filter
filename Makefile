CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

BIN := xdp_filter_kern.o xdp_filter_user.o httpd.o server
CLANG_FLAGS = -I. \
        -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
        -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
        -Wno-gnu-variable-sized-type-not-at-end \
        -Wno-address-of-packed-member -Wno-tautological-compare \
        -Wno-unknown-warning-option  \
        -O2 -Wall -emit-llvm

LDLIBS := -lelf -lbpf

all: $(BIN)

%_kern.o: %_kern.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - |      \
        $(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

xdp_filter_user.o: xdp_filter_user.c
	cc xdp_filter_user.c  -lelf -lbpf -c -o xdp_filter_user.o

server: xdp_filter_user.o httpd.o
	gcc -o server $^ -lbpf

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c

clean::
	$(RM) $(BIN)