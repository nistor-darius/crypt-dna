.PHONY: clean all

CXX := g++
CXXFLAGS := -Wall -Wextra -g 
OPENSSL_FLAGS := $(shell pkg-config --cflags --libs openssl)
TARGET := bin/crypt-dna
SRC := $(wildcard src/*.cpp)
OBJ := $(SRC:.cpp=.o)
INC := -I include

all: $(TARGET)

%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(INC) -c $< -o $@

$(TARGET): $(OBJ)
	$(CXX) $^ -o $@  $(OPENSSL_FLAGS)

clean:
	@echo "Cleaning up object files..."
	rm -f $(OBJ)