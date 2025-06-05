# Define the C++ compiler
CXX = g++

# Define the C++ standard
CXXFLAGS = -g -Wall -Wextra -std=c++17 

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    # macOS-specific settings
    CXXFLAGS += -I/opt/homebrew/include -L/opt/homebrew/lib
else
    # Assume Linux (or other)
    
endif

# Define libraries to link
# -l specifies the libraries to link against (e.g., -lssl links libssl.a or libssl.so)
LIBS = -lssl -lcrypto -lpthread

ifeq ($(shell test -f /etc/redhat-release && echo yes),yes)
    LIBS += -lstdc++fs
endif

# Define the source file
SRCS = server.cpp

# Define the executable name (derived from the source file name)
TARGET = $(basename $(SRCS))

.PHONY: all clean

# Default target: builds the executable
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LIBS) -o $(TARGET)

# Clean target: removes the compiled executable
clean:
	rm -f $(TARGET)
