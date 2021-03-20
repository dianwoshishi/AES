#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <cstdlib>
#include "AES.h"

using namespace std;

#define mem_size 1024*1024

#define DEBUG 1
#define fN 10

void ECB(AES& aes, uint8_t* key)
{
    
    for(int i = 1; i <= fN; i++){
#ifdef DEBUG
    clock_t time_start=clock();
#endif // DEBUG
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
            ofstream enFile(filename + ".ecb.en", ios::binary | ios::out);  //以二进制写模式打开文件
            if (!enFile) {
                cout << "New file open error." << endl;
                return ;
            }

            
            
            // aes.printHexArray(plain, length);
            out = aes.EncryptECB(plain, length, key,  len);
            enFile.write((char*)out, len);
            enFile.close();
            // aes.printHexArray(out, length);
        }

        {
            ofstream deFile(filename + ".ecb.de", ios::binary | ios::out);  //以二进制写模式打开文件
            if (!deFile) {
                cout << "New file open error." << endl;
                return ;
            }

            out = aes.DecryptECB(out, length, key);
            // aes.printHexArray(out, length);
            deFile.write((char*)out, len);
            deFile.close();
        }


        delete []plain;
        // delete []out;
#ifdef DEBUG
    clock_t time_end=clock();
    cout<<"time use:"<<1000*(time_end-time_start)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG

    }

}
void CBC(AES& aes, uint8_t* key, uint8_t* iv)
{
    for(int i = 1; i <= fN; i++){
#ifdef DEBUG
    clock_t time_start=clock();
#endif // DEBUG
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
        
        ofstream enFile(filename + ".cbc.en", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!enFile) {
            cout << "New file open error." << endl;
            return ;
        }

        
        unsigned int len = 0;
        // aes.printHexArray(plain, length);
        unsigned char *out = aes.EncryptCBC(plain, length, key, iv, len);
        enFile.write((char*)out, len);
        enFile.close();
        // aes.printHexArray(out, length);

        ofstream deFile(filename + ".cbc.de", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!deFile) {
            cout << "New file open error." << endl;
            return ;
        }

        out = aes.DecryptCBC(out, length, key, iv);
        deFile.write((char*)out, len);
        deFile.close();
        delete []plain;
        delete []out;
#ifdef DEBUG
    clock_t time_end=clock();
    cout<<"time use:"<<1000*(time_end-time_start)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG

    }
}

void OFB(AES& aes, uint8_t* key, uint8_t* iv)
{
    
    for(int i = 1; i <= fN; i++){
#ifdef DEBUG
    clock_t time_start=clock();
#endif // DEBUG
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
        
        ofstream enFile(filename + ".ofb.en", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!enFile) {
            cout << "New file open error." << endl;
            return ;
        }

        
        unsigned int len = 0;
        // aes.printHexArray(plain, length);
        unsigned char *out = aes.EncryptOFB(plain, length, key, iv, len);
        enFile.write((char*)out, len);
        enFile.close();
        // aes.printHexArray(out, length);

        ofstream deFile(filename + ".ofb.de", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!deFile) {
            cout << "New file open error." << endl;
            return ;
        }

        out = aes.DecryptOFB(out, length, key, iv);
        deFile.write((char*)out, len);
        deFile.close();
        delete []plain;
        delete []out;
#ifdef DEBUG
    clock_t time_end=clock();
    cout<<"time use:"<<1000*(time_end-time_start)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG

    }

}

void CFB(AES& aes, uint8_t* key, uint8_t* iv)
{
    
    for(int i = 1; i <= fN; i++){
#ifdef DEBUG
    clock_t time_start=clock();
#endif // DEBUG
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
        
        ofstream enFile(filename + ".cfb.en", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!enFile) {
            cout << "New file open error." << endl;
            return ;
        }

        
        unsigned int len = 0;
        // aes.printHexArray(plain, length);
        unsigned char *out = aes.EncryptCFB(plain, length, key, iv, len);
        enFile.write((char*)out, len);
        enFile.close();
        // aes.printHexArray(out, length);

        ofstream deFile(filename + ".cfb.de", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!deFile) {
            cout << "New file open error." << endl;
            return ;
        }

        out = aes.DecryptCFB(out, length, key, iv);
        deFile.write((char*)out, len);
        deFile.close();
        delete []plain;
        delete []out;

#ifdef DEBUG
    clock_t time_end=clock();
    cout<<"time use:"<<1000*(time_end-time_start)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG

    }

}

void CTR(AES& aes, uint8_t* key, uint8_t* iv)
{
    
    for(int i = 1; i <= fN; i++){
#ifdef DEBUG
    clock_t time_start=clock();
#endif // DEBUG
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
        
        ofstream enFile(filename + ".ctr.en", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!enFile) {
            cout << "New file open error." << endl;
            return ;
        }

        
        unsigned int len = 0;
        // aes.printHexArray(plain, length);
        unsigned char *out = aes.EncryptCTR(plain, length, key, iv, len);
        enFile.write((char*)out, len);
        enFile.close();
        // aes.printHexArray(out, length);

        ofstream deFile(filename + ".ctr.de", ios::binary | ios::out);  //以二进制写模式打开文件
        if (!deFile) {
            cout << "New file open error." << endl;
            return ;
        }

        out = aes.DecryptCTR(out, length, key, iv);
        deFile.write((char*)out, len);
        deFile.close();
        delete []plain;
        delete []out;

#ifdef DEBUG
    clock_t time_end=clock();
    cout<<"time use:"<<1000*(time_end-time_start)/(double)CLOCKS_PER_SEC<<"ms"<<endl;
#endif // DEBUG

    }

}

#define random(a,b) (rand()%(b-a)+a)
uint8_t *getNonce(uint8_t n)
{
    uint8_t *nonce = new uint8_t[n];    
    srand((int)time(0));  // 产生随机种子  把0换成NULL也行
    for (int i = 0; i < n; i++)
    {
        nonce[i] = random(0x00, 0xff);
    }
    return nonce;
}

#define ploy 0x13f
int main(int argc, char *argv[])
{
	cout << "hello world" << endl;

    AES aes(128);

    aes.genSBox(ploy);//0x11b,0x11d,0x13f
    aes.genInvSBox(ploy);

    // unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    unsigned char iv[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };


    cout << "ecb" << endl;
    ECB(aes, key);
    cout << "cbc" << endl;
    CBC(aes, key, iv);
    cout << "cfb" << endl;
    CFB(aes, key, iv);
    cout << "ofb" << endl;
    OFB(aes, key, iv);

    cout << "ctr" << endl;
    // uint8_t *nonces = new getNonce(16);
    CTR(aes, key, iv);

	return 0;
}