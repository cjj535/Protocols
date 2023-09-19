#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

int SM2_sign(const EC_GROUP* g, unsigned char *r, unsigned char *s, const unsigned char* m, const unsigned char *Z, const BIGNUM *dA){
    // A1
    int m_len = strlen((char*)m);
    unsigned char m_bar[512];
    memset(m_bar,0,sizeof(m_bar));
    unsigned_str_cpy(m_bar, Z, 32);
    unsigned_str_cpy(m_bar+32, m, m_len);

    // A2
    unsigned char e[33];
    SM3_Hash(m_bar, 32+m_len, e, &hash_output_bytes);
    // std::cout<<"e: ";printstr(e,32);

    while(true){
        // A3
        BIGNUM *k=BN_new();
        RandomGen(k,n);

        // A4
        EC_POINT *K=EC_POINT_new(g);
        EC_POINT_mul(g, K, k, NULL, NULL, ctx);
        BIGNUM *x1=BN_new(),*y1=BN_new();
        if(!EC_POINT_get_affine_coordinates_GFp(g, K, x1, y1, ctx)){
            std::cout<<"Failed to transfer to P_x and P_y"<<endl;
            return -1;
        }

        // A5
        BIGNUM *e_bn=BN_new(), *r_bn=BN_new(), *s_bn=BN_new();
        BN_bin2bn(e, 32, e_bn);
        BN_mod_add(r_bn, e_bn, x1, n, ctx);

        if(BN_is_zero(r_bn)) continue;
        BIGNUM *rk=BN_new();
        BN_add(rk, r_bn, k);
        if(BN_cmp(rk, n)==0) continue;

        // A6
        BIGNUM *tmp1=BN_new(), *tmp2=BN_new(), *tmp3=BN_new();
        BN_add(tmp1, dA, BN_value_one());
        BN_mod_inverse(tmp2, tmp1, n, ctx);
        BN_mod_mul(tmp3, dA, r_bn, n, ctx);
        BN_sub(tmp3, k, tmp3);
        BN_mod_mul(s_bn, tmp2, tmp3, n, ctx);

        if(BN_is_zero(s_bn)) continue;

        // A7
        BN_bn2bin(r_bn, r);
        BN_bn2bin(s_bn, s);
        // std::cout<<"r: ";printbn(r_bn);
        // std::cout<<"s: ";printbn(s_bn);
        break;
    }
    
    return 0;
}

int SM2_verify(const EC_GROUP* g, const unsigned char *r, const unsigned char *s, const unsigned char* m, const unsigned char *Z, const EC_POINT *PA){
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

int GenZ(const EC_GROUP* g, const BIGNUM* a, const BIGNUM* b, unsigned char *Z, const char *ID, const int id_len, const EC_POINT *P){
    unsigned char hash_str[256];
    memset(hash_str, 0, sizeof(hash_str));
    hash_str[0]=(id_len*8)/256;
    hash_str[1]=(id_len*8)%256;
    unsigned_str_cpy(&hash_str[2], (unsigned char*)ID, id_len);
    BN_bn2bin(a, &hash_str[id_len+2]);
    BN_bn2bin(b, &hash_str[id_len+2+32]);
    point2str(g, G, &hash_str[id_len+2+64]);
    point2str(g, P, &hash_str[id_len+2+64*2]);
    memset(Z, 0, 33);
    SM3_Hash(hash_str, id_len+2+64*3, Z, &hash_output_bytes);

    // std::cout<<"Z_CA: ";printstr(Z, 32);
    return 0;
}
