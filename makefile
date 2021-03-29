TARGET = main.out
# CC = g++
gprof		= -pg
DEBUG		= -O3 $(gprof)
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
	(seq 10 | xargs -i dd if=/dev/random of=tmp_file/{}.dat bs=500 count=400 ) > /dev/null
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
# gprof介绍.gprof是GNU profiler工具。可以显示程序运行的“flatprofile”，包括每个函数的调用次数，每个函数消耗的处理器时间。也可以显示“调用图”，包括函数的调用关系，每个函数调用花费了多少时间。还可以显示“注释的源代码”，是程序源代码的一个复本，标记有程序中每行代码的执行次数。
	gprof $(TARGET)
	
# 清理中间文件
clean:
	make clean_gen
	-rm -rf $(OBJ) $(TARGET)
	cd gtest;make clean
