#include <random>
#include <iostream>
#include <string.h>
#include <openssl/sha.h>

const int lambda = 256;

class MyBignum {
public:
    MyBignum(){
        for(int i=0;i<4;i++) n[i]=0;
    }
    MyBignum(unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d){
        n[0]=a;
        n[1]=b;
        n[2]=c;
        n[3]=d;
    }
    MyBignum(const MyBignum& t){}
    ~MyBignum(){}
    
    void print(){
        for(int i=0;i<3;i++)
            std::cout<<std::hex<<n[i]<<" ";
        std::cout<<std::hex<<n[3]<<std::endl;
    }
    
    void printstr(){
        // std::cout<<std::uppercase<<std::hex<<n[0];
        // std::cout<<std::uppercase<<std::hex<<n[1]<<std::endl;
        char output[65];
        memset(output,0,sizeof(output));
        for(int i=0;i<2;i++) {
            unsigned long long tmp = n[i];
            for(int j=0;j<16;j++){
                unsigned long long tmp1=tmp%16;
                if(tmp1>9){
                    output[i*16+15-j]='A'+(tmp1-10);
                }
                else{
                    output[i*16+15-j]='0'+tmp1;
                }
                tmp/=16;
            }
        }
        std::cout<<output<<std::endl;
        // for(int i=0;i<len;i++) cout<<hex<<(int)print[i];cout<<endl;
        return;
    }

    unsigned long long n[4];
};

void ExclusiveOR(MyBignum* c, MyBignum* a, MyBignum* b){
    c->n[0]=a->n[0]^b->n[0];
    c->n[1]=a->n[1]^b->n[1];
    c->n[2]=a->n[2]^b->n[2];
    c->n[3]=a->n[3]^b->n[3];
}

void bncpy(MyBignum* a, MyBignum* b){
    a->n[0]=b->n[0];
    a->n[1]=b->n[1];
    a->n[2]=b->n[2];
    a->n[3]=b->n[3];
}

bool isEqual(MyBignum* a, MyBignum* b){
    if((a->n[0]==b->n[0])&&(a->n[1]==b->n[1])&&(a->n[2]==b->n[2])&&(a->n[3]==b->n[3])){
        return true;
    }
    else{
        return false;
    }
}

void str_concat(unsigned char *dst, unsigned char *src1, unsigned char *src2)
{
    strcpy((char*)dst,(char*)src1);
    strcat((char*)dst,(char*)src2);
}

void Str2Bn(MyBignum* bn, unsigned char* str, size_t len){
    unsigned char bn_str[32];
    if(len<32){
        unsigned char zeros[32-len];
        memset(zeros, 0, sizeof(zeros));
        str_concat(bn_str, zeros, str);
    }
    else{
        for(int i=0;i<32;i++){
            bn_str[i]=str[i];
        }
    }
    for(int i=0;i<4;i++){
        for(int j=0;j<8;j++){
            bn->n[i]=(bn->n[i]*(1<<8))+(unsigned long long)(unsigned char)bn_str[i*8+j];
        }
    }
    return;
}

void Bn2Str(unsigned char* str, MyBignum* bn){
    for(int i=0;i<4;i++){
        unsigned long long tmp=bn->n[i];
        for(int j=0;j<8;j++){
            str[(i+1)*8-j-1]=tmp%(1<<8);
            tmp=tmp>>8;
        }
    }
    str[32]='\0';
    return;
}

void Hash(MyBignum* bn, unsigned char* input, size_t len){
    unsigned char output[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char*)input, len);
    SHA256_Final(output, &ctx);
    Str2Bn(bn, (unsigned char*)output, 32);
}
