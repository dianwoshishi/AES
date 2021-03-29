#include <iostream>
#include <algorithm>
#include <fstream>
#include <string>
#include <ctime>
#include <cstdlib>

#include "AES.h"

using namespace std;

#define mem_size 1024*1024

#define DEBUG 1
#define fN 10 //测试文件的数量


typedef unsigned char* (AES::*pEncryptWithoutIV)(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int &outLen);
typedef unsigned char* (AES::*pDecryptWithoutIV)(unsigned char in[], unsigned int inLen, unsigned  char key[]);
typedef unsigned char* (AES::*pEncryptWithIV)(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char *iv, unsigned int &outLen);
typedef unsigned char* (AES::*pDecryptWithIV)(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char *iv);


void testWithoutIV(AES& aes, uint8_t* key, pEncryptWithoutIV encrypt, pDecryptWithoutIV decrypt, string mode)
{
    transform(mode.begin(),mode.end(),mode.begin(),::toupper);
    clock_t total = 0;
#ifdef DEBUG
    clock_t time_start=clock();
#endif // DEBUG
    for(int i = 1; i <= fN; i++){
        string filename = "tmp_file/" + to_string(i) + ".dat";
        ifstream inFile(filename, ios::binary | ios::in);  //以二进制读模式打开文件
        if (!inFile) {
            cout << "Source file open error." << filename<<  endl;
            return ;
        }
        unsigned int l, length;
        l = inFile.tellg();
        inFile.seekg(0, ios::end);
        length = inFile.tellg();
        inFile.seekg(0, ios::beg);

        uint8_t *plain = new uint8_t[length];
        
        inFile.read((char*)plain, length);

        inFile.close();
        unsigned int len = 0;
        unsigned char *out;
        {
            ofstream enFile(filename + "."+ mode +".en", ios::binary | ios::out);  //以二进制写模式打开文件
            if (!enFile) {
                cout << "New file open error." << endl;
                return ;
            }

            
#ifdef DEBUG
    clock_t en_time_start=clock();
#endif // DEBUG                   
            // aes.printHexArray(plain, length);
            out = (aes.*encrypt)(plain, length, key,  len);
 #ifdef DEBUG
    clock_t en_time_end=clock();
    total += en_time_end-en_time_start;
    cout<<"encrypt time use:"<<1000*(en_time_end-en_time_start)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG           
            enFile.write((char*)out, len);
            enFile.close();
            // aes.printHexArray(out, length);
        }

        {
            ofstream deFile(filename + "." + mode +".de", ios::binary | ios::out);  //以二进制写模式打开文件
            if (!deFile) {
                cout << "New file open error." << endl;
                return ;
            }
#ifdef DEBUG
    clock_t de_time_start=clock();
#endif // DEBUG    
            out = (aes.*decrypt)(out, length, key);
#ifdef DEBUG
    clock_t de_time_end=clock();
    total += de_time_end-de_time_start;
    cout<<"decrypt time use:"<<1000*(de_time_end-de_time_start)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG
            printf("%s_AES Decryption: %s\n", mode.c_str(), 0 == memcmp((char*) plain, (char*) out, length) ? "\033[32mSUCCESS!\033[0m" : "\033[**31m**FAILURE!\033[**0m**");
            // aes.printHexArray(out, length);
            deFile.write((char*)out, len);
            deFile.close();
        }


        delete []plain;
        delete []out;


    }
#ifdef DEBUG
    cout<<"total time use:"<<1000*(total)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG

}

void testWithIV(AES& aes, uint8_t* key, unsigned char *iv, pEncryptWithIV encrypt, pDecryptWithIV decrypt, string mode)
{
    transform(mode.begin(),mode.end(),mode.begin(),::toupper);
    clock_t total = 0;
    for(int i = 1; i <= fN; i++){
        string filename = "tmp_file/" + to_string(i) + ".dat";
        ifstream inFile(filename, ios::binary | ios::in);  //以二进制读模式打开文件
        if (!inFile) {
            cout << "Source file open error." << filename<<  endl;
            return ;
        }
        unsigned int l, length;
        l = inFile.tellg();
        inFile.seekg(0, ios::end);
        length = inFile.tellg();
        inFile.seekg(0, ios::beg);
        // length = 16;

        uint8_t *plain = new uint8_t[length];
        
        inFile.read((char*)plain, length);

        inFile.close();
        
        ofstream enFile(filename + "."+ mode +".en", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!enFile) {
            cout << "New file open error." << endl;
            return ;
        }

#ifdef DEBUG
    clock_t en_time_start=clock();
#endif // DEBUG       
        unsigned int len = 0;
        // aes.printHexArray(plain, length);
        unsigned char *out = (aes.*encrypt)(plain, length, key, iv, len);

#ifdef DEBUG
    clock_t en_time_end=clock();
    total += en_time_end-en_time_start;
    cout<<"encrypt time use:"<<1000*(en_time_end-en_time_start)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG
        enFile.write((char*)out, len);
        enFile.close();
        // aes.printHexArray(out, length);

        ofstream deFile(filename + "."+ mode +".de", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!deFile) {
            cout << "New file open error." << endl;
            return ;
        }
#ifdef DEBUG
    clock_t de_time_start=clock();
#endif // DEBUG       
        out = (aes.*decrypt)(out, length, key, iv);
#ifdef DEBUG
    clock_t de_time_end=clock();
    total += de_time_end-de_time_start;
    cout<<"decrypt time use:"<<1000*(de_time_end-de_time_start)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG
        printf("%s_AES Decryption: %s\n",mode.c_str(), 0 == memcmp((char*) plain, (char*) out, length) ? "\033[32mSUCCESS!\033[0m" : "\033[**31m**FAILURE!\033[**0m**");
        deFile.write((char*)out, len);
        deFile.close();
        delete []plain;
        delete []out;
    }
#ifdef DEBUG
    cout<<"total time use:"<<1000*(total)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG
}

void ReadBytes(char* filename, uint32_t start, uint32_t len, unsigned char* buf){
    ifstream inFile(filename, ios::binary | ios::in);  //以二进制读模式打开文件
    if (!inFile) {
        cout << "Source file open error." << filename<<  endl;
        return ;
    }
    unsigned int l, length;
    l = inFile.tellg();
    inFile.seekg(0, ios::end);
    length = inFile.tellg();
    if(start > length || (start + len > length))//参数是否超过
        return ;
    inFile.seekg(start, ios::beg);
    
    inFile.read((char*)buf, len);

    inFile.close();
}

//设置S盒的不可约多项式，从0x1xx代表x^8 + xxx
#define ploy 0x13f


int main(int argc, char *argv[])
{
	cout << "hello world" << endl;

    AES aes(128);

    aes.genSBox(ploy);//0x11b,0x11d,0x13f,0x17b
    aes.genInvSBox(ploy);

    // unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    // unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    unsigned char key[16] = {0};
    // unsigned char iv[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
    ReadBytes("tmp_file/key.dat", 0, 16, key);
    unsigned char iv[16] = {0};
    ReadBytes("tmp_file/key.dat", 0, 16, iv);

    cout << "ecb" << endl;
    testWithoutIV(aes, key, &AES::EncryptECB, &AES::DecryptECB, "ecb");

    cout << "cbc" << endl;
    testWithIV(aes, key,iv,  &AES::EncryptCBC, &AES::DecryptCBC, "cbc");

    cout << "cfb" << endl;
    testWithIV(aes, key,iv,  &AES::EncryptCFB, &AES::DecryptCFB, "cfb");

    cout << "ofb" << endl;
    testWithIV(aes, key,iv,  &AES::EncryptOFB, &AES::DecryptOFB, "ofb");

    cout << "ctr" << endl;
    testWithIV(aes, key,iv,  &AES::EncryptCTR, &AES::DecryptCTR, "ctr");

    cout << "xts" << endl;
    testWithIV(aes, key,iv,  &AES::EncryptXTS, &AES::DecryptXTS, "xts");

	return 0;
}