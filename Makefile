# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
MAIN_GO=safebox/main.go
BINARY_DIR=safebox
BINARY_NAME=main
BINARY_UNIX=$(BINARY_NAME)_unix
MODE_GENKEY=-g
MODE_SETUP=-s
MODE_RELEASE=-r
MODE_MOUNT=-m
MODE_UNMOUNT=-u
ZONE_NAME=safezone1

all: test build

.PHONY: clean

clean:
		$(GOCLEAN)
		rm -f $(BINARY_DIR)/$(BINARY_NAME)
		rm -f $(BINARY_DIR)/$(BINARY_UNIX)

build:
		$(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME) -v  $(MAIN_GO)

test:
		./$(BINARY_DIR)/$(BINARY_NAME) $(MODE_GENKEY)
		dd if=/dev/zero of=/home/silenceender/zone.fs bs=1M count=16
		sleep 3s
		./$(BINARY_DIR)/$(BINARY_NAME) $(MODE_SETUP) $(ZONE_NAME)
		mke2fs /dev/mapper/$(ZONE_NAME)
		./$(BINARY_DIR)/$(BINARY_NAME) $(MODE_RELEASE) $(ZONE_NAME)
		./$(BINARY_DIR)/$(BINARY_NAME) $(MODE_MOUNT) $(ZONE_NAME)
		sleep 3s
		./$(BINARY_DIR)/$(BINARY_NAME) $(MODE_UNMOUNT) $(ZONE_NAME)

run:
		$(GOBUILD) -o $(BINARY_DIR)/$(BINARY_NAME) -v ./...
		./$(BINARY_DIR)/$(BINARY_NAME)

# Cross compilation
build-linux:
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_DIR)/$(BINARY_UNIX) -v
