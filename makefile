TARGET = main.out
# CC = g++
DEBUG		= -O3
CFLAGS		= $(DEBUG) -Wall
SRC = $(wildcard *.cpp)
OBJ = $(patsubst %.cpp, %.o, $(SRC))

#make指令默认执行命令 
ALL: $(TARGET)
	make gen
	./$(TARGET)
	@echo "结果输出在tmp_file文件夹"


#  
$(TARGET): $(OBJ)
	$(CXX) $(CFLAGS) -o $@ $^ 
 
%.o: %.cpp
	$(CXX) $(CFLAGS) -c $< -o $@

# 生成测试文件，存放在tmp_file目录下，每个文件随机5*500个字节，总共随机生成10个文件
gen:
	# make clean_gen
	(seq 10 | xargs -i dd if=/dev/random of=tmp_file/{}.dat bs=500 count=5 ) > /dev/null
	dd if=/dev/random of=tmp_file/key.dat bs=16 count=1
	dd if=/dev/random of=tmp_file/iv.dat bs=16 count=1
# 清空生成的测试文件
clean_gen:
	rm -rf tmp_file
	mkdir tmp_file
# 如果有googletest的话，生成单元测试，并执行
test:
	make -C gtest
	./gtest/test
	
# 清理中间文件
clean:
	make clean_gen
	-rm -rf $(OBJ) $(TARGET)
	cd gtest;make clean
