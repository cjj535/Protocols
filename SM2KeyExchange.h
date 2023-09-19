#include <unistd.h>
#include <string.h>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "utils.h"

int SM2(Client *clt, Server_info *ser_info){
    // communication
    ssize_t w_size, r_size;
    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd < 0){
        cout<<"SM2 error: socket failed!"<<endl;
        return -1;
    }

    struct sockaddr_in cli;
    memset(&cli,0,sizeof(sockaddr_in));
    cli.sin_family = AF_INET;
    cli.sin_addr.s_addr = inet_addr(ser_info->addr);
    cli.sin_port = htons(ser_info->port);
    cout<<"try to connect to "<<inet_ntoa(cli.sin_addr)<<endl;
    int isConnect = connect(sockfd,(sockaddr*)&cli,sizeof(cli));
    if(isConnect != 0){
        cout<<"error: connect to Server failed!"<<endl;
        return -1;
    }

    cout<<"Establishing session key with Server "<<inet_ntoa(cli.sin_addr)<<endl;

    BIGNUM *P_S_x = BN_new(), *P_S_y = BN_new(), *x_1 = BN_new(), *y_1 = BN_new(), *x_1_bar = BN_new(), *bn_tmp1 = BN_new(), *t_C = BN_new(), 
    *x_2 = BN_new(), *y_2 = BN_new(), *x_2_bar = BN_new(), *x_U = BN_new(), *y_U = BN_new(), *r_C = BN_new();
    unsigned char message_buf[512];
    unsigned char S_S[33], S_1[33], S_C[33];
    unsigned char tmp_hash_output[33];
    unsigned char hash_str[256];
    
    EC_POINT *P_S = EC_POINT_new(g), *R_C = EC_POINT_new(g), *R_S = EC_POINT_new(g), 
    *U = EC_POINT_new(g), *point_tmp1 = EC_POINT_new(g), *point_tmp2 = EC_POINT_new(g);

    // set public key P_S
    BN_hex2bn(&P_S_x, P_S_x_str), BN_hex2bn(&P_S_y, P_S_y_str);
    if(!EC_POINT_set_affine_coordinates_GFp(g, P_S, P_S_x, P_S_y, ctx)){
        cout<<"Failed to transfer to P_S"<<endl;
    }
    // A1: random generator generates 1 < r_C < n
    RandomGen(r_C, n);
    // printbn(r_C);
    // BN_hex2bn(&r_C, const_r_C_str);
    
    // A2: compute R_C = r_C * G
    EC_POINT_mul(g, R_C, NULL, G, r_C, ctx);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // prepare certificate
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    // A3: send option 1, ID_C, R_C to Server S
    memset(message_buf, 0, sizeof(message_buf));
    message_buf[0]='1';
    int id_len = strlen(ID_C);
    unsigned_str_cpy(&message_buf[1], (unsigned char*)ID_C, id_len);
    message_buf[id_len+1]='\n';
    EC_POINT_point2oct(g, R_C, POINT_CONVERSION_COMPRESSED, &message_buf[id_len+2], hash_output_bytes+1, ctx);
    // add cert
    // Cert2Str(clt->cert, &message_buf[id_len+2+33]);
    unsigned_str_cpy(&message_buf[id_len+2+33], clt->cert, clt->cert_len);
    // cout<<clt->cert_len<<" ";printstr(clt->cert,clt->cert_len);
    w_size = write(sockfd, message_buf, 256);
    // std::cout<<"W1: ";printstr(message_buf, 256);

    // A4: compute x_1_bar = 2^w + (x_1 & (2^w-1))
    if(!EC_POINT_get_affine_coordinates_GFp(g, R_C, x_1, y_1, ctx)){
        cout<<"Failed to transfer"<<endl;
    }
    // cout<<"x_1 "<<endl;printbn(x_1);
    // cout<<"y_1 "<<endl;printbn(y_1);
    BN_copy(x_1_bar,x_1);
    BN_mask_bits(x_1_bar, clt->w);
    BN_set_bit(x_1_bar, clt->w);
    // cout<<"x_1_bar "<<endl;printbn(x_1_bar);
    
    // A5: compute t_C = (d_C + x_1_bar * r_C) mod n
    BN_mod_mul(bn_tmp1, x_1_bar, r_C, n, ctx);
    BN_mod_add(t_C, clt->d_C, bn_tmp1, n, ctx);
    // cout<<"t_C "<<endl;printbn(t_C);
    
    // receive message R_S || S_S
    memset(message_buf, 0, sizeof(message_buf));
    r_size = read(sockfd, message_buf, 65);
    // std::cout<<"R1: ";printstr(message_buf, 70);
    memset(S_S, 0, sizeof(S_S));
    EC_POINT_oct2point(g, R_S, message_buf, 33, ctx);
    unsigned_str_cpy(S_S, &message_buf[33], 32);
    // printstr(message_buf, 65);
    // printstr(S_S, 32);

    // A6: verify whether R_S is on curve and compute x_2_bar
    if(EC_POINT_is_on_curve(g, R_S, ctx)!=1){
        cout<<"R_S is not on curve"<<endl;
        cout<<"S reject"<<endl;
        return -1;
    }
    if(!EC_POINT_get_affine_coordinates_GFp(g, R_S, x_2, y_2, ctx)){
        cout<<"Failed to transfer R_S"<<endl;
    }
    // cout<<"R_S"<<endl;
    // printbn(x_2);
    // printbn(y_2);
    BN_copy(x_2_bar,x_2);
    BN_mask_bits(x_2_bar, clt->w);
    BN_set_bit(x_2_bar, clt->w);

    // A7: compute point U = [h * t_A](P_S + [x_2_bar] R_S) = (x_U, y_U)
    EC_POINT_mul(g, point_tmp1, NULL, R_S, x_2_bar, ctx);
    EC_POINT_add(g, point_tmp2, P_S, point_tmp1, ctx);
    BN_mod_mul(bn_tmp1, h, t_C, n, ctx);
    EC_POINT_mul(g, U, NULL, point_tmp2, bn_tmp1, ctx);
    if(!EC_POINT_get_affine_coordinates_GFp(g, U, x_U, y_U, ctx)){
        cout<<"Failed to transfer U"<<endl;
    }
    // cout<<"U"<<endl;
    // printbn(x_U);
    // printbn(y_U);
    // check whether U is infinity point O
    if(EC_POINT_is_at_infinity(g, U)){
        cout<<"U is O"<<endl;
        return -1;
    }

    // A8: compute K_C = KDF(x_U || y_U || Z_C || Z_S, klen)
    memset(hash_str, 0, sizeof(hash_str));
    BN_bn2bin(x_U, &hash_str[0]);
    BN_bn2bin(y_U, &hash_str[32]);
    unsigned_str_cpy(&hash_str[32*2], clt->Z_C, 32);
    unsigned_str_cpy(&hash_str[32*3], ser_info->Z_S, 32);
    memset(clt->K_C, 0, sizeof(clt->K_C));
    KDF(hash_str, 32*4, clt->K_C, K_bytes, hash_output_bytes);
    // cout<<"K_C "<<endl;printstr(clt->K_C, hash_output_bytes);

    // A9: compute S_1
    memset(hash_str, 0, sizeof(hash_str));
    BN_bn2bin(x_U, &hash_str[0]);
    unsigned_str_cpy(&hash_str[32*1], clt->Z_C, 32);
    unsigned_str_cpy(&hash_str[32*2], ser_info->Z_S, 32);
    BN_bn2bin(x_1, &hash_str[32*3]);
    BN_bn2bin(y_1, &hash_str[32*4]);
    BN_bn2bin(x_2, &hash_str[32*5]);
    BN_bn2bin(y_2, &hash_str[32*6]);
    memset(tmp_hash_output, 0, sizeof(tmp_hash_output));
    SM3_Hash(hash_str, 32*7, tmp_hash_output, &hash_output_bytes);

    memset(hash_str, 0, sizeof(hash_str));
    hash_str[0]=0x02;
    BN_bn2bin(y_U, &hash_str[1]);
    unsigned_str_cpy(&hash_str[1+32], tmp_hash_output, 32);
    memset(S_1, 0, sizeof(S_1));
    SM3_Hash(hash_str, 1+32*2, S_1, &hash_output_bytes);
    // cout<<"S_1 "<<endl;printstr(S_1, hash_output_bytes);

    // check whether S_S is equal to S_1
    for(int i=0;i<32;i++){
        if(S_1[i]!=S_S[i]) {
            cout<<"S_1 is not equal to S_S"<<endl;
            return -1;
        }
    }

    // A10: compute S_C
    memset(hash_str, 0, sizeof(hash_str));
    hash_str[0]=0x03;
    BN_bn2bin(y_U, &hash_str[1]);
    unsigned_str_cpy(&hash_str[1+32], tmp_hash_output, 32);
    memset(S_C, 0, sizeof(S_C));
    SM3_Hash(hash_str, 1+32*2, S_C, &hash_output_bytes);
    // cout<<"S_C "<<endl;printstr(S_C, hash_output_bytes);

    // send S_C to Server S
    memset(message_buf, 0, sizeof(message_buf));
    unsigned_str_cpy(message_buf, S_C, 32);
    w_size = write(sockfd, message_buf, 33);
    // std::cout<<"W2: ";printstr(message_buf, 40);

    // receive message
    memset(message_buf, 0, sizeof(message_buf));
    r_size = read(sockfd, message_buf, 1);
    // std::cout<<"R2: ";printstr(message_buf, 70);
    if(message_buf[0] != '1'){
        cout<<"Failed to confirm with Server"<<endl;
        return -1;
    }

    close(sockfd);

    std::cout<<"Received reply from Server, key agreement is completed!!!"<<std::endl;
    std::cout<<std::endl;

    // get key
    memset(clt->key, 0, sizeof(clt->key));
    unsigned_str_cpy(clt->key, clt->K_C, K_bytes);

    // free
    BN_free(P_S_x);
    BN_free(P_S_y);
    BN_free(x_1);
    BN_free(y_1);
    BN_free(x_1_bar);
    BN_free(bn_tmp1);
    BN_free(t_C);
    BN_free(x_2);
    BN_free(y_2);
    BN_free(x_2_bar);
    BN_free(x_U);
    BN_free(y_U);
    BN_free(r_C);
    
    EC_POINT_free(P_S);
    EC_POINT_free(U);
    EC_POINT_free(point_tmp1);
    EC_POINT_free(point_tmp2);

    return 0;
}

int SM2(Client_info* clt, unsigned char* message_buf, int sockfd, int id_len, bool isInit){
    // new
    BIGNUM *r_S = BN_new(), *P_C_x = BN_new(), *P_C_y = BN_new(),
    *x_2 = BN_new(), *y_2 = BN_new(), *x_2_bar = BN_new(), *bn_tmp1 = BN_new(), *t_S = BN_new(), 
    *x_1 = BN_new(), *y_1 = BN_new(), *x_1_bar = BN_new(), *x_V = BN_new(), *y_V = BN_new();
    EC_POINT *P_C = EC_POINT_new(g), *R_S = EC_POINT_new(g), *R_C = EC_POINT_new(g), *V = EC_POINT_new(g), 
            *point_tmp1 = EC_POINT_new(g), *point_tmp2 = EC_POINT_new(g);
    unsigned char hash_str[256];
    unsigned char tmp_hash_output[33];
    unsigned char S_S[33], S_2[33], S_C[33];

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // verify certificate and derive public key (Z_C)
    // message buffer: R_C(33), cert(64+64+id_len)
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    unsigned_str_cpy(clt->cert, message_buf+33, 32*4+id_len);
    if(Verify_cer(message_buf+33, id_len)!=0){
        std::cout<<"the certificate is unvalid"<<std::endl;
        close(sockfd);
        pthread_exit(NULL);
    }

    unsigned char P_C_x_bin[33],P_C_y_bin[33];
    unsigned_str_cpy(P_C_x_bin, clt->cert, 32);
    unsigned_str_cpy(P_C_y_bin, (clt->cert)+32, 32);
    BN_bin2bn(P_C_x_bin, 32, P_C_x);
    BN_bin2bn(P_C_y_bin, 32, P_C_y);
    if(!EC_POINT_set_affine_coordinates_GFp(g, P_C, P_C_x, P_C_y, ctx)){
        std::cout<<"Failed to transfer to P_C"<<endl;
        return -1;
    }
    clt->init(P_C);

    // std::cout<<"R_C "<<endl;printstr(message_buf, 33);
    EC_POINT_oct2point(g, R_C, message_buf, 33, ctx);

    // -------------------------------------------------------------------------------------------
    // Key agreement
    // -------------------------------------------------------------------------------------------

    // B1: random generator generates 1 < r_S < n
    RandomGen(r_S, n);
    // printbn(r_S);
    // BN_hex2bn(&r_S, const_r_S_str);

    // BIGNUM *x_x=BN_new(),*y_y=BN_new();
    // if(EC_POINT_get_affine_coordinates_GFp(g, P_C, x_x, y_y, ctx)){
    //     std::cout<<"P_C"<<endl;
    //     printbn(x_x);
    //     printbn(y_y);
    // }
    
    // B2: compute R_S = r_S * G
    EC_POINT_mul(g, R_S, NULL, G, r_S, ctx);

    // B3: compute x_2_bar = 2^w + (x_2 & (2^w-1))
    if(!EC_POINT_get_affine_coordinates_GFp(g, R_S, x_2, y_2, ctx)){
        std::cout<<"Failed to transfer R_S"<<endl;
        close(sockfd);
        pthread_exit(NULL);
    }
    // std::cout<<"x_2 "<<endl;printbn(x_2);
    // std::cout<<"y_2 "<<endl;printbn(y_2);
    BN_copy(x_2_bar,x_2);
    BN_mask_bits(x_2_bar, ser.w);
    BN_set_bit(x_2_bar, ser.w);
    // std::cout<<"x_2_bar "<<endl;printbn(x_2_bar);
    
    // B4: compute t_S = (d_S + x_2_bar * r_S) mod n
    BN_mod_mul(bn_tmp1, x_2_bar, r_S, n, ctx);
    BN_mod_add(t_S, ser.d_S, bn_tmp1, n, ctx);
    // std::cout<<"t_S "<<endl;printbn(t_S);
    
    // B5: verify whether R_C is on curve and compute x_1_bar
    if(EC_POINT_is_on_curve(g, R_C, ctx)!=1){
        std::cout<<"R_C is not on curve"<<endl;
        std::cout<<"C reject"<<endl;
        close(sockfd);
        pthread_exit(NULL);
    }
    if(!EC_POINT_get_affine_coordinates_GFp(g, R_C, x_1, y_1, ctx)){
        std::cout<<"Failed to transfer R_C"<<endl;
        close(sockfd);
        pthread_exit(NULL);
    }
    // std::cout<<"R_C"<<endl;
    // printbn(x_1);
    // printbn(y_1);
    BN_copy(x_1_bar,x_1);
    BN_mask_bits(x_1_bar, ser.w);
    BN_set_bit(x_1_bar, ser.w);
    // std::cout<<"x_1_bar "<<endl;printbn(x_1_bar);

    // B6: compute point V = [h * t_S](P_C + [x_1_bar] R_C) = (x_V, y_V)
    EC_POINT_mul(g, point_tmp1, NULL, R_C, x_1_bar, ctx);
    EC_POINT_add(g, point_tmp2, P_C, point_tmp1, ctx);
    BN_mod_mul(bn_tmp1, h, t_S, n, ctx);
    EC_POINT_mul(g, V, NULL, point_tmp2, bn_tmp1, ctx);
    if(!EC_POINT_get_affine_coordinates_GFp(g, V, x_V, y_V, ctx)){
        std::cout<<"Failed to transfer"<<endl;
        close(sockfd);
        pthread_exit(NULL);
    }
    // std::cout<<"V"<<endl;
    // printbn(x_V);
    // printbn(y_V);
    // check whether V is infinity point O
    if(EC_POINT_is_at_infinity(g, V)){
        std::cout<<"V is O"<<endl;
        close(sockfd);
        pthread_exit(NULL);
    }

    // B7: compute K_S = KDF(x_V || y_V || Z_A || Z_B, klen)
    memset(hash_str, 0, sizeof(hash_str));
    BN_bn2bin(x_V, &hash_str[0]);
    BN_bn2bin(y_V, &hash_str[32]);
    unsigned_str_cpy(&hash_str[32*2], clt->Z_C, 32);
    unsigned_str_cpy(&hash_str[32*3], ser.Z_S, 32);
    memset(ser.K_S, 0, sizeof(ser.K_S));
    KDF(hash_str, 32*4, ser.K_S, K_bytes, hash_output_bytes);
    // printstr(ser.K_S, hash_output_bytes);

    // B8: compute S_S
    memset(hash_str, 0, sizeof(hash_str));
    BN_bn2bin(x_V, &hash_str[0]);
    unsigned_str_cpy(&hash_str[32*1], clt->Z_C, 32);
    unsigned_str_cpy(&hash_str[32*2], ser.Z_S, 32);
    BN_bn2bin(x_1, &hash_str[32*3]);
    BN_bn2bin(y_1, &hash_str[32*4]);
    BN_bn2bin(x_2, &hash_str[32*5]);
    BN_bn2bin(y_2, &hash_str[32*6]);
    
    memset(tmp_hash_output, 0, sizeof(tmp_hash_output));
    SM3_Hash(hash_str, 32*7, tmp_hash_output, &hash_output_bytes);

    memset(hash_str, 0, sizeof(hash_str));
    hash_str[0]=0x02;
    BN_bn2bin(y_V, &hash_str[1]);
    unsigned_str_cpy(&hash_str[1+32], tmp_hash_output, 32);
    memset(S_S, 0, sizeof(S_S));
    SM3_Hash(hash_str, 1+32*2, S_S, &hash_output_bytes);
    // printstr(S_S, hash_output_bytes);

    // B9: send R_S || S_S to Client C
    // memset(message_buf, 0, sizeof(message_buf));
    memset(message_buf, 0, 512);
    int oct_len = EC_POINT_point2oct(g, R_S, POINT_CONVERSION_COMPRESSED, message_buf, hash_output_bytes+3, ctx);
    unsigned_str_cpy(&message_buf[oct_len], S_S, 32);
    // printstr(message_buf,65);
    int w_size = write(sockfd, message_buf, 65);
    // std::cout<<"W1: ";printstr(message_buf, 70);

    // B10: compute S_2
    memset(hash_str, 0, sizeof(hash_str));
    hash_str[0]=0x03;
    BN_bn2bin(y_V, &hash_str[1]);
    unsigned_str_cpy(&hash_str[1+32], tmp_hash_output, 32);
    memset(S_2, 0, sizeof(S_2));
    SM3_Hash(hash_str, 1+32*2, S_2, &hash_output_bytes);
    // printstr(S_2, hash_output_bytes);

    // receive message
    // memset(message_buf, 0, sizeof(message_buf));
    memset(message_buf, 0, 512);
    int r_size = read(sockfd, message_buf, 33);
    // std::cout<<"R2: ";printstr(message_buf, 40);
    memset(S_C, 0, sizeof(S_C));
    unsigned_str_cpy(S_C, message_buf, 32);
    
    // check whether S_C is equal to S_2
    for(int i=0;i<32;i++){
        if(S_2[i]!=S_C[i]) {
            std::cout<<"S_2 is not equal to S_C"<<endl;
            close(sockfd);
            pthread_exit(NULL);
        }
    }

    // send confirm to Client
    // memset(message_buf, 0, sizeof(message_buf));
    memset(message_buf, 0, 512);
    message_buf[0]='1';
    w_size = write(sockfd, message_buf, 1);
    // std::cout<<"W2: ";printstr(message_buf, 40);

    std::cout<<"Key agreement is completed!!!"<<endl;
    std::cout<<endl;
    memset(clt->key, 0, sizeof(clt->key));
    unsigned_str_cpy(clt->key, ser.K_S, K_bytes);
    clt->t = time(NULL);
    std::cout<<"Session Key: "<<endl;printstr(clt->key,K_bytes);

    // free
    // BN_free(P_C_x);
    // BN_free(P_C_y);
    BN_free(r_S);
    BN_free(x_1);
    BN_free(y_1);
    BN_free(x_1_bar);
    BN_free(bn_tmp1);
    BN_free(t_S);
    BN_free(x_2);
    BN_free(y_2);
    BN_free(x_2_bar);
    BN_free(x_V);
    BN_free(y_V);

    EC_POINT_free(P_C);
    EC_POINT_free(R_C);
    EC_POINT_free(R_S);
    EC_POINT_free(V);
    EC_POINT_free(point_tmp1);
    EC_POINT_free(point_tmp2);
    
    return 0;
}
