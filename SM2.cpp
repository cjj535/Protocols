#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

int SM2_verify(unsigned char *r, unsigned char *s, unsigned char* m, unsigned char *Z, EC_POINT *PA){
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
    unsigned char m_bar[512];
    unsigned_str_cpy(m_bar, Z, 32);
    unsigned_str_cpy(m_bar+32, m, m_len);

    // B4
    unsigned char e[33];
    SM3_Hash(m_bar, 32+m_len, e, &hash_output_bytes);
    BIGNUM *e_bn=BN_new();
    BN_bin2bn(e, 32, e_bn);

    // B5
    BIGNUM *t=BN_new();
    BN_mod_add(t, r_bn, s_bn, n, ctx);
    if(BN_is_zero(t)) {
        std::cout<<"verify error in B5"<<std::endl;
        return -1;
    }

    // B6
    EC_POINT *tmp=EC_POINT_new(g);
    EC_POINT_mul(g, tmp, s_bn, PA, t, ctx);
    BIGNUM *x1=BN_new(),*y1=BN_new();
    if(!EC_POINT_get_affine_coordinates_GFp(g, tmp, x1, y1, ctx)){
        std::cout<<"Failed to transfer to P_x and P_y"<<endl;
        return -1;
    }
    
    // B7
    BIGNUM *R=BN_new();
    BN_mod_add(R, e_bn, x1, n, ctx);
    if(BN_cmp(R, r_bn)!=0){
        std::cout<<"verify error in B7"<<std::endl;
        return -1;
    }

    return 0;
}
