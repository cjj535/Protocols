#include <string.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "./utils.h"

int ECDSA_sign(const EC_GROUP* g,unsigned char* r, unsigned char* s, const unsigned char *m, const BIGNUM *dA) {
    // A1
    int m_len = strlen((char*)m);
    unsigned char z[33];
    SM3_Hash(m, m_len, z, &hash_output_bytes);

    // A2
    BIGNUM *k=BN_new();
    RandomGen(k,n);

    // A3
    EC_POINT *K=EC_POINT_new(g);
    EC_POINT_mul(g, K, k, NULL, NULL, ctx);
    BIGNUM *x1=BN_new(),*y1=BN_new();
    if(!EC_POINT_get_affine_coordinates_GFp(g, K, x1, y1, ctx)){
        std::cout<<"Failed to transfer to P_x and P_y"<<endl;
        return -1;
    }
    if(BN_is_zero(x1)) {
        cout<<"r is zero"<<endl;
        return -1;
    }

    // A4
    BIGNUM *z_bn=BN_new(), *s_bn=BN_new();
    BN_bin2bn(z, 32, z_bn);

    BIGNUM *tmp1=BN_new(), *tmp2=BN_new(), *tmp3=BN_new();
    BN_mod_inverse(tmp1, k, n, ctx);

    BN_mod_mul(tmp2, dA, x1, n, ctx);
    BN_add(tmp3, z_bn, tmp2);
    BN_mod_mul(s_bn, tmp1, tmp3, n, ctx);
    if(BN_is_zero(s_bn)) {
        cout<<"s is zero"<<endl;
        return -1;
    }

    // A5
    BN_bn2bin(x1, r);
    BN_bn2bin(s_bn, s);
}

int ECDSA_verify(const EC_GROUP* g, const unsigned char *r, const unsigned char *s, const unsigned char* m, const EC_POINT *PA){
    // B1 & B2
    // std::cout<<"r: ";printstr(r, 32);
    // std::cout<<"s: ";printstr(s, 32);
    BIGNUM *r_bn=BN_new(), *s_bn=BN_new();
    BN_bin2bn(r, 32, r_bn);
    BN_bin2bn(s, 32, s_bn);
    if((BN_cmp(r_bn, BN_value_one())<0)||
        (BN_cmp(s_bn, BN_value_one())<0)||
        (BN_cmp(n, r_bn)<=0)||
        (BN_cmp(n, s_bn)<=0)){
        std::cout<<"verify error in B1 and B2"<<std::endl;
        return -1;
    }

    // B3
    int m_len = strlen((char*)m);
    unsigned char z[33];
    SM3_Hash(m, m_len, z, &hash_output_bytes);
    BIGNUM *z_bn=BN_new();
    BN_bin2bn(z, 32, z_bn);

    // B4
    BIGNUM *u1=BN_new(), *tmp1=BN_new();
    BN_mod_inverse(tmp1, s_bn, n, ctx);
    BN_mod_mul(u1, z_bn, tmp1, n, ctx);

    // B5
    BIGNUM *u2=BN_new();
    BN_mod_mul(u2, r_bn, tmp1, n, ctx);
    if(BN_is_zero(u2)) {
        std::cout<<"verify error in B5"<<std::endl;
        return -1;
    }

    // B6
    EC_POINT *tmp=EC_POINT_new(g);
    EC_POINT_mul(g, tmp, u1, PA, u2, ctx);
    if(EC_POINT_is_at_infinity(g,tmp)){
        cout<<"P is at infinity"<<endl;
        return -1;
    }
    BIGNUM *x1=BN_new(),*y1=BN_new();
    if(!EC_POINT_get_affine_coordinates_GFp(g, tmp, x1, y1, ctx)){
        std::cout<<"Failed to transfer to P_x and P_y"<<endl;
        return -1;
    }
    
    // B7
    if(BN_cmp(x1, r_bn)!=0){
        std::cout<<"verify error in B7"<<std::endl;
        return -1;
    }

    return 0;
}
