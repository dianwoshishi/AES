Target = test
CFLAGES = -O2 -Wall
gtest	= -lgtest -lgtest_main 
SRC = $(wildcard *.cpp)
OBJ = $(patsubst %.cpp, %.o, $(SRC))

all:$(Target)

$(Target): $(OBJ)
	$(CXX) $(FLAGS) -g -pthread ../AES.cpp $^ $(gtest) -o $@

clean:
	-rm -rf $(OBJ) $(Target)
