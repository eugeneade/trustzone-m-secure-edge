# Command-line build for the Secure and Non-Secure images (NUCLEO-L552ZE-Q).
#
# Uses the toolchain bundled with STM32CubeIDE. Override CUBEIDE_PLUGINS (or
# TOOLCHAIN / PROGRAMMER directly) if your install lives elsewhere.
#
#   make            build both images into build/
#   make flash      program both images and reset the board
#   make clean
#
#   make ISOLATION_TEST=1 flash
#                   NS app ends by reading Secure flash directly, to show the
#                   access is blocked (SecureFault reported on the UART)

CUBEIDE_PLUGINS ?= C:/ST/STM32CubeIDE_2.2.0/STM32CubeIDE/plugins
TOOLCHAIN  ?= $(CUBEIDE_PLUGINS)/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.14.3.rel1.win32_1.0.100.202602081740/tools/bin/arm-none-eabi-
PROGRAMMER ?= $(CUBEIDE_PLUGINS)/com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.win32_2.2.500.202603051304/tools/bin/STM32_Programmer_CLI

CC      := $(TOOLCHAIN)gcc
OBJCOPY := $(TOOLCHAIN)objcopy
SIZE    := $(TOOLCHAIN)size

DEV  := third_party/cmsis-device-l5
CORE := third_party/cmsis-core/CMSIS/Core/Include
MBEDTLS := third_party/mbedtls
BUILD := build

ARCH := -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard
COMMON_CFLAGS := $(ARCH) -std=c11 -O2 -g3 -Wall -Wextra -ffunction-sections -fdata-sections \
                 -DSTM32L552xx -I$(DEV)/Include -I$(CORE) -ISecure/Inc
COMMON_LDFLAGS := $(ARCH) --specs=nano.specs --specs=nosys.specs -Wl,--print-memory-usage

# ---- Secure image ----------------------------------------------------------
S_SRCS := Secure/Src/main.c \
          Secure/Src/crypto_service.c \
          $(MBEDTLS)/library/sha256.c \
          $(MBEDTLS)/library/platform_util.c \
          $(DEV)/Source/Templates/system_stm32l5xx_s.c \
          $(DEV)/Source/Templates/gcc/startup_stm32l552xx.s
S_CFLAGS := $(COMMON_CFLAGS) -mcmse -I$(DEV)/Include/Templates \
            -I$(MBEDTLS)/include -DMBEDTLS_CONFIG_FILE='"secure_mbedtls_config.h"'
S_ELF    := $(BUILD)/secure.elf
S_IMPLIB := $(BUILD)/secure_nsclib.o

# ---- Non-Secure image ------------------------------------------------------
NS_SRCS := NonSecure/Src/main.c \
           $(DEV)/Source/Templates/system_stm32l5xx_ns.c \
           $(DEV)/Source/Templates/gcc/startup_stm32l552xx.s
# ST's system_stm32l5xx_ns.c calls SECURE_SystemCoreClockUpdate() without a prototype.
NS_CFLAGS := $(COMMON_CFLAGS) -include secure_nsc.h
ifeq ($(ISOLATION_TEST),1)
NS_CFLAGS += -DISOLATION_TEST
endif
NS_ELF    := $(BUILD)/nonsecure.elf

# The NS image always relinks (~1 s) so toggling ISOLATION_TEST never leaves a stale build.
.PHONY: all flash clean FORCE_NS
all: $(S_ELF:.elf=.hex) $(NS_ELF:.elf=.hex)
FORCE_NS:

$(S_ELF) $(S_IMPLIB) &: $(S_SRCS) $(wildcard Secure/Inc/*.h) Makefile
	@mkdir -p $(BUILD)
	$(CC) $(S_CFLAGS) $(S_SRCS) $(COMMON_LDFLAGS) \
	    -T$(DEV)/Source/Templates/gcc/linker/STM32L552xE_FLASH_s.ld \
	    -Wl,--cmse-implib,--out-implib=$(S_IMPLIB) \
	    -Wl,-Map=$(BUILD)/secure.map -o $(S_ELF)
	$(SIZE) $(S_ELF)

$(NS_ELF): $(NS_SRCS) $(S_IMPLIB) Makefile FORCE_NS
	@mkdir -p $(BUILD)
	$(CC) $(NS_CFLAGS) $(NS_SRCS) $(S_IMPLIB) $(COMMON_LDFLAGS) \
	    -T$(DEV)/Source/Templates/gcc/linker/STM32L552xE_FLASH_ns.ld \
	    -Wl,--gc-sections -Wl,-Map=$(BUILD)/nonsecure.map -o $(NS_ELF)
	$(SIZE) $(NS_ELF)

%.hex: %.elf
	$(OBJCOPY) -O ihex $< $@

flash: all
	"$(PROGRAMMER)" -c port=SWD mode=UR -d $(S_ELF:.elf=.hex) -d $(NS_ELF:.elf=.hex) -v -rst

clean:
	rm -rf $(BUILD)
