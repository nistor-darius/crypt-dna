.PHONY: clean all

CXX := g++
CXXFLAGS := -Wall -Wextra -g 
TARGET := bin/crypt-dna
SRC := $(wildcard src/*.cpp)
OBJ := $(SRC:.cpp=.o)
INC := -I include

all: $(TARGET)

%.o: src/%.cpp
	@echo "Building $@ ..."
	$(CXX) $(CXXFLAGS) $(INC) -c $< -o $@


$(TARGET): $(OBJ)
	@echo "Building $@ ..."
	$(CXX) $(CXXFLAGS) $^ -o $@

clean:
	@echo "Cleaning up object files..."
	rm -f $(OBJ)