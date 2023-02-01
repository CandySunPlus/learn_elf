LD = ld
NASM = nasm
CC = gcc
RM = rm -rf
TARGET_PATH = ./target/release
SRC_PATH = ./src


objects := hello.o hello-dl.o msg.o nodata.o hello-rel.o
objects := $(addprefix $(TARGET_PATH)/,$(objects))

no_pie_elfbins := hello nodata
pie_elfbins := hello-dl-pie hello-pie hello-rel-pie
shared_elfbins := hello-dl
dynamic_libs := libmsg.so

elfbins := $(addprefix $(TARGET_PATH)/,$(no_pie_elfbins) $(pie_elfbins) $(shared_elfbins))
libs := $(addprefix $(TARGET_PATH)/,$(dynamic_libs))

$(TARGET_PATH)/%: $(TARGET_PATH)/%.o
	$(LD) -o $@ $< 
	
$(TARGET_PATH)/lib%.so: $(TARGET_PATH)/%.o
	$(LD) -shared -o $@ $<

$(TARGET_PATH)/%-pie: $(TARGET_PATH)/%.o
	$(LD) -pie --dynamic-linker /lib/ld-linux-x86-64.so.2 -o $@ $<

$(TARGET_PATH)/%-dl-pie: $(TARGET_PATH)/%.o $(TARGET_PATH)/msg.o
	$(LD) -pie --dynamic-linker /lib/ld-linux-x86-64.so.2 -o $@ $^

$(TARGET_PATH)/%-dl: $(libs) $(TARGET_PATH)/%.o 
	$(LD) -pie --dynamic-linker /lib/ld-linux-x86-64.so.2 -o $@ $^

$(TARGET_PATH)/entry_point: $(SRC_PATH)/entry_point.c
	$(CC) -o $@ $< 

$(TARGET_PATH)/%.o: $(SRC_PATH)/%.asm
	$(NASM) -f elf64 $< -o $@ 

all: $(TARGET_PATH)/entry_point $(elfbins)

.PHONY: clean

clean:
	$(RM) $(elfbins) $(libs) $(objects) $(TARGET_PATH)/entry_point
