.PHONY: dirs

# important directories
SRC    = src
BIN    = bin
OBJ    = obj
INC    = include
LIBBPF = libbpf

# compilation related parameters
LLC        = llc
CLANG      = clang
CC         = gcc
CFLAGS     = -I $(INC) -I $(LIBBPF)/include -I $(LIBBPF)/build/usr/include
LDFLAGS    = -L $(LIBBPF)/build -l:libbpf.a -lelf -lz
BPF_CFLAGS = $(CFLAGS) -D__KERNEL__ -D__BPF_TRACING__ -emit-llvm -O2
LLC_FLAGS  = -march=bpf -filetype=obj
CFLAGS += $(shell pkg-config --cflags json-c)
LDFLAGS += $(shell pkg-config --libs json-c)

# identify sources and create object file targets
SOURCES_XDP = $(wildcard $(SRC)/*_kern.c)
SOURCES_USR = $(wildcard $(SRC)/*_user.c)
HTTPD_AG = $(wildcard $(SRC)/httpd.c)
OBJECTS_XDP = $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES_XDP))
OBJECTS_USR = $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES_USR))
OBJECTS_AG = $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(HTTPD_AG))

# top level rule
build: dirs $(BIN)/loader $(OBJECTS_XDP)

# non-persistent folder creation rule
dirs:
	mkdir -p $(OBJ) $(BIN)

# final USR binary generation rule
$(BIN)/loader: $(OBJECTS_USR) $(OBJECTS_AG)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Server agent object generation rule
$(OBJ)/httpd.o: $(SRC)/httpd.c
	$(CC) $(CFLAGS) -c -o $@ $<

# USR object generation rule
$(OBJ)/%_user.o: $(SRC)/%_user.c
	$(CC) $(CFLAGS) -c -o $@ $<

# XDP object generation rule
$(OBJ)/%_kern.o: $(SRC)/%_kern.c
	$(CLANG) $(BPF_CFLAGS) -c -o - $< | \
	$(LLC)   $(LLC_FLAGS)  -o $@

# clean rule
clean:
	rm -rf $(OBJ) $(BIN)
