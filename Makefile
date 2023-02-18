LD = ld
NASM = nasm
CC = gcc
RM = rm -f
TARGET_PATH = ./target/release
SRC_PATH = ./src


objects := $(wildcard $(TARGET_PATH)/*.o)

no_pie_elfbins := hello nodata
pie_elfbins := hello-dl-pie hello-pie hello-rel-pie bss-pie bss2-pie bss3-pie
shared_elfbins := hello-dl
dynamic_libs := libmsg.so  libfoo.so

nolibc_elfbins := hello-nolibc ifunc-nolibc
example_elfbins := chimera

elfbins := $(addprefix $(TARGET_PATH)/,$(no_pie_elfbins) $(pie_elfbins) $(shared_elfbins) $(nolibc_elfbins) $(example_elfbins))
libs := $(addprefix $(TARGET_PATH)/,$(dynamic_libs))

$(TARGET_PATH):
	mkdir -p $@

$(TARGET_PATH)/%.o: $(SRC_PATH)/%.asm
	$(NASM) -f elf64 $< -o $@ 

$(TARGET_PATH)/%: $(TARGET_PATH)/%.o
	$(LD) -o $@ $< 

	
$(TARGET_PATH)/lib%.so: $(TARGET_PATH)/%.o
	$(LD) -shared -o $@ $<

$(TARGET_PATH)/%-pie: $(TARGET_PATH)/%.o
	$(LD) -pie --dynamic-linker /lib/ld-linux-x86-64.so.2 -o $@ $<

$(TARGET_PATH)/%-dl-pie: $(TARGET_PATH)/%-dl.o $(TARGET_PATH)/msg.o
	$(LD) -pie --dynamic-linker /lib/ld-linux-x86-64.so.2 -o $@ $^

$(TARGET_PATH)/%-dl: $(TARGET_PATH)/%-dl.o
	$(LD) -pie -rpath '$$ORIGIN' --disable-new-dtags --dynamic-linker /lib/ld-linux-x86-64.so.2 -o $@ $< -lmsg -L $(TARGET_PATH)

$(TARGET_PATH)/entry_point: $(SRC_PATH)/entry_point.c | $(TARGET_PATH)
	$(CC) -o $@ $< 

$(TARGET_PATH)/%nolibc: $(SRC_PATH)/%nolibc.c
	$(CC) -nostartfiles -nodefaultlibs -fPIC -L$(TARGET_PATH) -Wl,-rpath='$$ORIGIN' -o $@ $<

$(TARGET_PATH)/chimera: $(SRC_PATH)/chimera.c $(TARGET_PATH)/libfoo.so
	$(CC) -nostartfiles -nodefaultlibs -fPIC -L$(TARGET_PATH) -Wl,-rpath='$$ORIGIN' -lfoo -o $@ $<
	
$(TARGET_PATH)/libfoo.so: $(SRC_PATH)/foo.c
	$(CC) -nostartfiles -nodefaultlibs -fPIC -shared -L$(TARGET_PATH) -Wl,-rpath='$$ORIGIN' -o $@ $<



.PHONY: clean all

all: $(TARGET_PATH)/entry_point $(libs) $(elfbins) 
clean:
	$(RM) $(elfbins) $(libs) $(objects) $(TARGET_PATH)/entry_point
