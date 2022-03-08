#include <iostream>
#include "aes.h"

using namespace std;

// 封装完成用法
int main()
{
    AES aes;

    aes.setType(AES::CBC);
    aes.setKey("1234567890123456");
    aes.setIv("asdfghjklzxcvbnm");

    std::cout << aes.decrypt(aes.encrypt("hello aes!")) << std::endl;
}
