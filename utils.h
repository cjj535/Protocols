#include <string.h>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/ec.h>

// #include <openssl/x509v3.h>
// #include <openssl/asn1.h>
// #include <openssl/x509.h>
// #include <openssl/x509_vfy.h>
// #include <openssl/pem.h>
// #include <openssl/bio.h>
// OpenSSL_add_all_algorithms();

using namespace std;

/**
 *hash function(SM3)
 *input: input(string)
 *output: output(unsighed char, 256)
 */
int SM3_Hash(unsigned char* input, size_t input_len, unsigned char* buffer, unsigned int* buf_len){
    if(input_len<=0){
        std::cout<<"Wrong param"<<endl;
        return -1;
    }
    
    memset(buffer,0,*buf_len);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // sm3
    if(!EVP_DigestInit_ex(ctx, EVP_sm3(), NULL)){
        std::cout<<"Failed to init"<<std::endl;
        return -1;
    }

    // update with each string
    if(!EVP_DigestUpdate(ctx, input, input_len)) {
        std::cout<<"Failed to update"<<std::endl;
        return -1;
    }

    // final hash result
    if(!EVP_DigestFinal_ex(ctx, buffer, buf_len)) {
        std::cout<<"Failed to final"<<std::endl;
        return -1;
    }

    // free
    EVP_MD_CTX_free(ctx);
    return 0;
}

/**
 *KDF(generate key function)
 *input: input(string)
 *output: output(unsighed char, klen)
 */
int KDF(unsigned char* input, size_t input_len, unsigned char* buffer, int klen, unsigned int hash_output_bytes){
    // init ct
    int ct=1;

    // ct: 1~seil(klen/256)
    for(;ct<=((klen+(hash_output_bytes-1))/hash_output_bytes);ct++){
        unsigned char s[256];
        memcpy(s, input, input_len);

        int tmp=ct;
        s[input_len]=tmp/(1<<24);
        tmp%=(1<<24);
        s[input_len+1]=tmp/(1<<16);
        tmp%=(1<<16);
        s[input_len+2]=tmp/(1<<8);
        tmp%=(1<<8);
        s[input_len+3]=tmp;

        if(SM3_Hash(s, input_len+4, &buffer[(ct-1)*hash_output_bytes], &hash_output_bytes)==-1){
            std::cout<<"Failed to generate key"<<endl;
            return -1;
        }
    }

    return 0;
}

/**
 * Random generator (generate random bignum)
 * input: 
 * output: output(BIGNUM r)
 */
int RandomGen(BIGNUM* r, BIGNUM* order){
    return BN_rand_range(r, order);
    // return BN_pseudo_rand_range(r, order);
}

/**
 * transform "FFFF" to 0xffff
 * return the bytes length of bin
 */
int hex2bin(char *str, size_t len, unsigned char *bin){
    if(len%2==0){
        int bin_len=len/2;
        for(int i=0;i<bin_len;i++){
            int byte_num=0;
            if(str[2*i]>='A'&&str[2*i]<='F'){
                byte_num+=((str[2*i]-'A'+10)<<4);
            }
            else{
                byte_num+=((str[2*i]-'0')<<4);
            }
            if(str[2*i+1]>='A'&&str[2*i+1]<='F'){
                byte_num+=(str[2*i+1]-'A'+10);
            }
            else{
                byte_num+=(str[2*i+1]-'0');
            }
            bin[i]=byte_num;
        }
        return bin_len;
    }
    else{
        int bin_len=len/2+1;
        int byte_num=0;
        if(str[0]>='A'&&str[0]<='F'){
            byte_num+=(str[0]-'A'+10);
        }
        else{
            byte_num+=(str[0]-'0');
        }
        bin[0]=byte_num;
        for(int i=1;i<bin_len;i++){
            byte_num=0;
            if(str[2*i-1]>='A'&&str[2*i-1]<='F'){
                byte_num+=((str[2*i-1]-'A'+10)<<4);
            }
            else{
                byte_num+=((str[2*i-1]-'0')<<4);
            }
            if(str[2*i]>='A'&&str[2*i]<='F'){
                byte_num+=(str[2*i]-'A'+10);
            }
            else{
                byte_num+=(str[2*i]-'0');
            }
            bin[i]=byte_num;
        }
        return bin_len;
    }
    return 0;
}

/**
 * EC_POINT to string
 * the string is char, because the hash input need be char, can't be unsigned char
 */
void point2str(EC_GROUP *g, const EC_POINT *_A, unsigned char *str) {
	BIGNUM *_x = BN_new();
	BIGNUM *_y = BN_new();
	if (!EC_POINT_get_affine_coordinates_GFp(g,_A,_x,_y,NULL)) {
		std::cout<<"Failed to tansfer"<<endl;
        return;
	}
	BN_bn2bin(_x, str);
	BN_bn2bin(_y, &str[32]);

	BN_free(_x);
	BN_free(_y);

	return;
}

/**
 * copy str: a <- b
 */
void unsigned_str_cpy(unsigned char *dst, unsigned char *src, size_t len){
    for(int i=0;i<len;i++){
        dst[i]=src[i];
    }
    return;
}

/**
 * print bn with hex form
 **/
void printbn(const BIGNUM *bn){
    char *print = BN_bn2hex(bn);
    int len=strlen(print);
    // cout<<len<<endl;
    for(int i=0;i<len;i++) std::cout<<hex<<print[i];
    std::cout<<endl;
}

/**
 * print bn with hex form
 **/
void printbn(BIGNUM *bn){
    char *print = BN_bn2hex(bn);
    int len=strlen(print);
    // cout<<len<<endl;
    for(int i=0;i<len;i++) std::cout<<hex<<print[i];
    std::cout<<endl;
}

/**
 * print str hex form
 **/
void printstr(unsigned char *print, size_t len){
    char output[len*3];
    memset(output,0,sizeof(output));
    for(int i=0;i<len;i++) {
        int tmp = (int)print[i];
        int tmp1 = tmp/(16);
        int tmp2 = tmp%(16);
        if(tmp1>9) {
            output[2*i] = 'A'+(tmp1-10);
        }
        else{
            output[2*i] = '0'+(tmp1-0);
        }
        if(tmp2>9) {
            output[2*i+1] = 'A'+(tmp2-10);
        }
        else{
            output[2*i+1] = '0'+(tmp2-0);
        }
    }
    std::cout<<output<<endl;
    // for(int i=0;i<len;i++) cout<<hex<<(int)print[i];cout<<endl;
    return;
}

AES_KEY aes_key;

/**
 * AES encrypt
 * input: msg,key
 * output: cpt
 */
int EncAES(unsigned char *cpt, unsigned char *key, unsigned char *msg){
    unsigned char iv[16]="012345678901234";
    AES_set_encrypt_key(key,128,&aes_key);
    AES_cbc_encrypt(msg, cpt, 16, &aes_key, iv, AES_ENCRYPT);

    return 0;
}

/**
 * AES decrypt
 * input: cpt,key
 * output: msg
 */
int DecAES(unsigned char *msg, unsigned char *key, unsigned char *cpt){
    unsigned char iv[16]="012345678901234";
    AES_set_decrypt_key(key,128,&aes_key);
    AES_cbc_encrypt(cpt, msg, 16, &aes_key, iv, AES_DECRYPT);

    return 0;
}


/**
 * SM4 encrypt
 * input: msg,key
 * output: cpt
 */
int EncSM4(unsigned char *cpt, unsigned char *key, unsigned char *msg){
    int out_len,out_padding_len;
    int msg_len = 16;
    // cout<<msg_len<<endl;
    unsigned char *iv;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    out_len = 0;
    EVP_EncryptUpdate(ctx, cpt, &out_len, msg, msg_len);
    out_padding_len = 0;
    EVP_EncryptFinal_ex(ctx, cpt+out_len, &out_padding_len);
    // std::cout<<"cpt_len: "<<out_len<<endl;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/**
 * SM4 decrypt
 * input: cpt,key
 * output: msg
 */
int DecSM4(unsigned char *msg, unsigned char *key, unsigned char *cpt){
    unsigned char *iv;
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    int msg_len,pad_len;
    int cpt_len=strlen((char*)cpt);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, iv)) {
        std::cout<<"EVP_DecryptInit_ex failed"<<std::endl;
    }
    EVP_CIPHER_CTX_set_padding(ctx,0);

    if (1 != EVP_DecryptUpdate(ctx, msg, &msg_len, cpt, cpt_len)) {
        std::cout<<"EVP_DecryptUpdate failed"<<std::endl;
    }
    // cout<<"msg_len: "<<msg_len<<" "<<msg<<endl;
    // if(0==(msg_len%16))
    // {
    //     EVP_CIPHER_CTX_set_padding(ctx,0);
    //     msg_len += 16;
    // }
    if(!EVP_DecryptFinal_ex(ctx, msg+msg_len, &pad_len))
    {
        std::cout<<"EVP_DecryptFinal failed"<<std::endl;
        return EXIT_FAILURE;
    }
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int Str2Cert(X509* cert, unsigned char* str){
    
    return 0;
}

int Cert2Str(X509* cert, unsigned char* str){
    
    return 0;
}
