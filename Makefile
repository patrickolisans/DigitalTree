CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g

SRC_DIR = src
BUILD_DIR = build
TARGET = $(BUILD_DIR)/firewall

SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/firewall_tree.c
OBJS = $(BUILD_DIR)/main.o $(BUILD_DIR)/firewall_tree.o

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c $(SRC_DIR)/firewall_tree.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/firewall_tree.o: $(SRC_DIR)/firewall_tree.c $(SRC_DIR)/firewall_tree.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
