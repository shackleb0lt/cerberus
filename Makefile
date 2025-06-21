# Comment below line to see actual linker and compiler flags while running makefile
.SILENT:

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Iinc
LDLIBS := #-lpthread
LDFLAGS := 

SRC_DIR := src
INC_DIR := inc
BUILD_DIR := bld

# Build modes and flags
DEBUG_FLAGS := -O0 -g -Wformat=2 -Wconversion -Wimplicit-fallthrough
RELEASE_FLAGS := -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -DNDEBUG
RELEASE_LDFLAGS := -s -Wl,-z,noexecstack -Wl,-z,defs -Wl,-z,nodump

#Source Files
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)

# Object files
SRC_OBJECTS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_FILES))

PING_OBJS := bld/packet_header.o bld/common.o bld/ping.o
# TRACERT_OBJS := bld/packet_header.o bld/common.o bld/trace.o

# Final executable
PING_TARGET := $(BUILD_DIR)/ping
# TRACERT_TARGET := $(BUILD_DIR)/tracert

# Default PING_TARGET
.PHONY: all
all: debug

# Debug build PING_TARGET
.PHONY: debug
debug: CFLAGS += $(DEBUG_FLAGS)
debug: LDFLAGS += $(LDLIBS)
debug: $(PING_TARGET) # $(TRACERT_TARGET)

# Release build PING_TARGET
.PHONY: release
release: CFLAGS += $(RELEASE_FLAGS)
release: LDFLAGS += $(RELEASE_LDFLAGS) $(LDLIBS)
release: $(PING_TARGET) $(TRACERT_TARGET)

$(TRACERT_TARGET) : $(SRC_OBJECTS)
	@echo "Linking executable $(TRACERT_TARGET)"
	$(CC) $(CFLAGS) $(TRACERT_OBJS) $(LDFLAGS) -o $(TRACERT_TARGET)

# Build executable PING_TARGET
$(PING_TARGET): $(SRC_OBJECTS)
	@echo "Linking executable $(PING_TARGET)"
	$(CC) $(CFLAGS) $(PING_OBJS) $(LDFLAGS) -o $(PING_TARGET)

# Compile source object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Create the build directory
$(BUILD_DIR):
	@echo "Creating build directory $(BUILD_DIR)"
	mkdir -p $(BUILD_DIR)

# Clean up build files
.PHONY: clean
clean:
	@echo "Cleaning up build files"
	rm -rf $(BUILD_DIR)