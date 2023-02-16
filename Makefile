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
dynamic_libs := libmsg.so

elfbins := $(addprefix $(TARGET_PATH)/,$(no_pie_elfbins) $(pie_elfbins) $(shared_elfbins))
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

$(TARGET_PATH)/hello-nolibc: $(SRC_PATH)/hello-nolibc.c
	$(CC) -nostartfiles -nodefaultlibs -o $@ $<

$(TARGET_PATH)/ifunc-nolibc: $(SRC_PATH)/ifunc-nolibc.c
	$(CC) -nostartfiles -nodefaultlibs -o $@ $<

.PHONY: clean all

all: $(TARGET_PATH)/entry_point $(TARGET_PATH)/hello-nolibc $(TARGET_PATH)/ifunc-nolibc $(libs) $(elfbins) 
clean:
	$(RM) $(elfbins) $(libs) $(objects) $(TARGET_PATH)/{entry_point,hello-nolibc,ifunc-nolibc}
