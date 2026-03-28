# File Integrity Monitor - Makefile
# Compiles all modules and links against OpenSSL and SQLite3
#
# Build:    make
# Clean:    make clean
# Debug:    make DEBUG=1

CC       = gcc
CFLAGS   = -Wall -Wextra -Wpedantic -std=c11 CFLAGS   = -Wall -Wextra -Wpedantic -std=c11 -D_DEFAULT_SOURCE
LDFLAGS  = -lssl -lcrypto -lsqlite3

# Debug vs Release
ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2
endif

# Source files
SRC_DIR  = src
SRCS     = $(SRC_DIR)/main.c \
           $(SRC_DIR)/scanner.c \
           $(SRC_DIR)/database.c \
           $(SRC_DIR)/reporter.c

HEADERS  = $(SRC_DIR)/fim_types.h \
           $(SRC_DIR)/scanner.h \
           $(SRC_DIR)/database.h \
           $(SRC_DIR)/reporter.h

# Output
TARGET   = fim

# Object files
OBJS     = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo ""
	@echo "Build complete: ./$(TARGET)"
	@echo "Run './$(TARGET) --help' for usage"

# Compile each .c file to .o
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(SRC_DIR)/*.o $(TARGET)
	@echo "Cleaned build artifacts"

# Remove database too
distclean: clean
	rm -f fim_data.db
	@echo "Removed database file"

.PHONY: all clean distclean
