# 使用说明
## 文件目录结构
- tmp_file 文件夹为生成的测试文件，及存放测试文件经过五种模式加解密的文件
  - 生成文件为：i.dat
  - 加密文件为：i.dat.en
  - 解密文件为：i.dat.de

- gtest 
  - googletest 单元测试文件

## Linux下运行指令说明
> make

生成测试文件并运行

> make gen

重新生成测试文件

> make clean_gen

清空测试文件

> make test

对AES的加解密功能进行单元测试

> make clean

清除中间文件

