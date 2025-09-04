################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (13.3.rel1)
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include Drivers/STM32F4xx_HAL_Driver/Src/subdir.mk
-include Core/Startup/subdir.mk
-include Core/Src/subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(S_DEPS)),)
-include $(S_DEPS)
endif
ifneq ($(strip $(S_UPPER_DEPS)),)
-include $(S_UPPER_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

OPTIONAL_TOOL_DEPS := \
$(wildcard ../makefile.defs) \
$(wildcard ../makefile.init) \
$(wildcard ../makefile.targets) \


BUILD_ARTIFACT_NAME := Test_STM32_CryptoLib
BUILD_ARTIFACT_EXTENSION := elf
BUILD_ARTIFACT_PREFIX :=
BUILD_ARTIFACT := $(BUILD_ARTIFACT_PREFIX)$(BUILD_ARTIFACT_NAME)$(if $(BUILD_ARTIFACT_EXTENSION),.$(BUILD_ARTIFACT_EXTENSION),)

# Add inputs and outputs from these tool invocations to the build variables 
EXECUTABLES += \
Test_STM32_CryptoLib.elf \

MAP_FILES += \
Test_STM32_CryptoLib.map \

SIZE_OUTPUT += \
default.size.stdout \

OBJDUMP_LIST += \
Test_STM32_CryptoLib.list \


# All Target
all: main-build

# Main-build Target
main-build: Test_STM32_CryptoLib.elf secondary-outputs

# Tool invocations
Test_STM32_CryptoLib.elf Test_STM32_CryptoLib.map: $(OBJS) $(USER_OBJS) C:\Users\Victor\ Pizarro\OneDrive\ -\ Universidad\ Técnica\ Federico\ Santa\ María\VP\Projects\Labthermics\STM32\ Software\Test_STM32_CryptoLib\STM32F401RETX_FLASH.ld makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-gcc -o "Test_STM32_CryptoLib.elf" @"objects.list" $(USER_OBJS) $(LIBS) -mcpu=cortex-m4 -T"C:\Users\Victor Pizarro\OneDrive - Universidad Técnica Federico Santa María\VP\Projects\Labthermics\STM32 Software\Test_STM32_CryptoLib\STM32F401RETX_FLASH.ld" --specs=nosys.specs -Wl,-Map="Test_STM32_CryptoLib.map" -Wl,--gc-sections -static -L"C:\Users\Victor Pizarro\OneDrive - Universidad Técnica Federico Santa María\VP\Projects\Labthermics\STM32 Software\Test_STM32_CryptoLib\Middlewares\ST\STM32_Cryptographic\lib" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -Wl,--start-group -lc -lm -Wl,--end-group
	@echo 'Finished building target: $@'
	@echo ' '

default.size.stdout: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-size  $(EXECUTABLES)
	@echo 'Finished building: $@'
	@echo ' '

Test_STM32_CryptoLib.list: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-objdump -h -S $(EXECUTABLES) > "Test_STM32_CryptoLib.list"
	@echo 'Finished building: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) Test_STM32_CryptoLib.elf Test_STM32_CryptoLib.list Test_STM32_CryptoLib.map default.size.stdout
	-@echo ' '

secondary-outputs: $(SIZE_OUTPUT) $(OBJDUMP_LIST)

fail-specified-linker-script-missing:
	@echo 'Error: Cannot find the specified linker script. Check the linker settings in the build configuration.'
	@exit 2

warn-no-linker-script-specified:
	@echo 'Warning: No linker script specified. Check the linker settings in the build configuration.'

.PHONY: all clean dependents main-build fail-specified-linker-script-missing warn-no-linker-script-specified

-include ../makefile.targets
