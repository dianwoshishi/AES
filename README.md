# 使用说明
## 不可约多项式
当前使用不可约多项式为：0x13F
$$
x^8 + x^5+x^4+x^3+x^2+x+1
$$

已测试多项式为:0x11b,0x11d,0x13f,0x17b

![有限域$$F_{2^8}$$上的8次不可约多项式](pic/ploy.png)
> 参考：https://wenku.baidu.com/view/59c3c573ba68a98271fe910ef12d2af90242a8e


## 文件目录结构
- tmp_file 文件夹为生成的测试文件，及存放测试文件经过五种模式加解密的文件
  - 生成文件为：i.dat
  - 加密文件为：i.dat.en
  - 解密文件为：i.dat.de
  - 测试秘钥为：key.dat
  - 测试iv为：iv.dat

- gtest 
  - googletest 单元测试文件

- pic README相关图片

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

