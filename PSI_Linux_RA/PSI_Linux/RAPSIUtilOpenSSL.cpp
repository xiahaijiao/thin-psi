//
//  RAPSIUtilOpenSSL.cpp
//  RASoftAlg
//
//  Created by john on 2020/6/11.
//  Copyright © 2020 China rongan. All rights reserved.
//

#include "RAPSIUtilOpenSSL.hpp"

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <stdint.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include "string.h"
#include <openssl/rsa.h>
#include <iostream>
#include<string.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fstream>

void genAddr();
void findAddr2();
void findAddr();
void genAddrRipple();
//char* en_base58(unsigned char* input)
char* de_base58(char* src);
int base58decode(const std::string input, int len, unsigned char* result);
int base58encode(const std::string input, int len, unsigned char result[]);
void findAddrThread();
void genRandom(char* res);
void getPubBase(char* priStr, char* baseG, char* pubStr);
using namespace std;
void testBtc2();
void test_next_y();


//文件入口函数
void bntest() {

	// cout << "bntest  文件入口函数" << endl;
	//testBNArithmetic2();
	//testAddress();

	//sha256();
	//genAddr();
	//findAddr();

	//精简pub
	//indAddr2();
//	testRipple();
	//testAddress();
	//查找附近点
	//testBtc2();
	test_next_y();

	//findAddr();
	//testBNArithmetic();
	//call1();

}

struct CurveParams {
	BIGNUM* p;
	BIGNUM* a;
	BIGNUM* b;
	EC_GROUP* group;
	EC_POINT* G;
	BIGNUM* order;

};
typedef struct CurveParams CurveParams;

CurveParams* g_curve_params;


#define DOMAIN_CHECK(c) ('0'<=(c)&&(c)<='9'||'a'<=(c)&&(c)<='f'||'A'<=(c)&&(c)<='F')


#define BASE58TABLE "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#include <openssl/sha.h>

std::string base58encode(const std::string& hexstring);

void hashSha256(unsigned char* puchMM, size_t uiMMLen, unsigned char* outEChar, unsigned  int* uiDigestLen) {
	//const EVP_MD* EVP_sha256(void);
	//const EVP_MD* EVP_ripemd160(void);

	const EVP_MD* mdType = EVP_sha256();
	EVP_MD_CTX* ctx_evp = EVP_MD_CTX_new();
	//         EVP_MD_CTX_init(ctx_evp);
	EVP_DigestInit_ex(ctx_evp, mdType, NULL);
	EVP_DigestUpdate(ctx_evp, puchMM, uiMMLen);
	EVP_DigestFinal_ex(ctx_evp, outEChar, uiDigestLen);
	EVP_MD_CTX_free(ctx_evp);


}


void hashripe160(unsigned char* puchMM, size_t uiMMLen, unsigned char* outEChar, unsigned  int* uiDigestLen) {


	const EVP_MD* mdType = EVP_ripemd160();
	EVP_MD_CTX* ctx_evp = EVP_MD_CTX_new();
	//         EVP_MD_CTX_init(ctx_evp);
	EVP_DigestInit_ex(ctx_evp, mdType, NULL);
	EVP_DigestUpdate(ctx_evp, puchMM, uiMMLen);
	EVP_DigestFinal_ex(ctx_evp, outEChar, uiDigestLen);
	EVP_MD_CTX_free(ctx_evp);


}


void raHashSha256(char* plain, int len, char* hash) {

	//    unsigned char *puchMM = malloc(sizeof(len+1));
	unsigned char* puchMM = (unsigned char*)malloc(len + 1);
	//void convertStrToUnChar(char* str, unsigned char* UnChar)
	convertStrToUnChar(plain, puchMM);
	//memcpy(puchMM, plain, len);
	unsigned char* outEchar = (unsigned char*)malloc(32 + 1);
	unsigned int outLen = 32;

	hashSha256(puchMM, len, outEchar, &outLen);

	char* outHash = (char*)malloc(64 + 1);
	memset(outHash, 0, 64 + 1);
	//    memcpy(outHash, outEchar, outLen);
	convertUnCharToStr(outHash, outEchar, outLen);
	strcpy(hash, outHash);

	//    unsigned char tmp[33] = {0};
	//    convertStrToUnChar(hash, tmp);

	//清理敏感数据
	memset(puchMM, 0, len);
	//strcpy(plain, "");

	free(puchMM);
	free(outEchar);
	free(outHash);

}


void raHashRipe160(char* plain, int len, char* hash) {

	//    unsigned char *puchMM = malloc(sizeof(len+1));
	unsigned char* puchMM = (unsigned char*)malloc(len + 1);
	//void convertStrToUnChar(char* str, unsigned char* UnChar)
	convertStrToUnChar(plain, puchMM);
	//memcpy(puchMM, plain, len);
	unsigned char* outEchar = (unsigned char*)malloc(32 + 1);
	unsigned int outLen = 32;

	hashripe160(puchMM, len, outEchar, &outLen);
	//20
	//cout << outLen << endl;

	char* outHash = (char*)malloc(64 + 1);
	memset(outHash, 0, 64 + 1);
	//    memcpy(outHash, outEchar, outLen);
	convertUnCharToStr(outHash, outEchar, outLen);
	strcpy(hash, outHash);

	//    unsigned char tmp[33] = {0};
	//    convertStrToUnChar(hash, tmp);

	//清理敏感数据
	memset(puchMM, 0, len);
	//strcpy(plain, "");

	free(puchMM);
	free(outEchar);
	free(outHash);

}

void sha256() {


	char s_buf[] = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6";
	char d_buf[10000];
	int s_len = strlen(s_buf);
	int d_len = 10000;
	//600FFE422B4E00731A59557A5CCA46CC183944191006324A447BDB2D98D4B408
	//raHashSha256(s_buf, strlen(s_buf)/2,d_buf);

	char s_buf2[] = "600FFE422B4E00731A59557A5CCA46CC183944191006324A447BDB2D98D4B408";
	//010966776006953D5567439E5E39F86A0D273BEE
	raHashRipe160(s_buf2, strlen(s_buf2) / 2, d_buf);


	cout << d_buf << endl;
}
void genAddr() {
	/*
	2.公钥
	3.sha256
	4..ripe160
	5.加版本
	6.sha256
	7.sha256
	8.后四位拼接到第5步之后
	9.base58编码
	*/
	//char* pubStr = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6";
	//char* pubStr = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
	char pubStr[256] = { 0 };
	cout << "pubstr:" << endl;
	cin >> pubStr;
	//char step3[100] = { 0 };
	cout << pubStr << endl;
	char step3[100] = { 0 };
	//char* step3 =(char*) malloc(1024);
	raHashSha256(pubStr, strlen(pubStr) / 2, step3);
	cout << "step3:" << step3 << endl;


	char Ripe160_step4[100] = { 0 };
	raHashRipe160(step3, strlen(step3) / 2, Ripe160_step4);

	cout << "step4:" << Ripe160_step4 << endl;

	char version_step5[100] = { 0 };
	sprintf(version_step5, "00%s", Ripe160_step4);
	cout << "step5:" << version_step5 << endl;

	char step6[100] = { 0 };
	raHashSha256(version_step5, strlen(version_step5) / 2, step6);
	cout << "step6:" << step6 << endl;

	char step7[100] = { 0 };

	raHashSha256(step6, strlen(step6) / 2, step7);
	cout << "step7:" << step7 << endl;

	char step8[100] = { 0 };
	char last4[10] = { 0 };
	//strncpy(last4, step7+ strlen(step7)-8, 8); 
	strncpy(last4, step7, 8);
	sprintf(step8, "%s%s", version_step5, last4);
	cout << "step8:" << step8 << endl;


	string hex_string = step8;

	//const char* step9 =  base58encode(hex_string).c_str();  //c_str()
	char step9[100] = { 0 };
	sprintf(step9, "%s", base58encode(hex_string).c_str());
	cout << "step9:" << base58encode(hex_string).c_str() << endl;
	cout << "step9:" << step9 << endl;


}


void genAddr2(char* pubStr, char* addrStr) {
	/*
	2.公钥
	3.sha256
	4..ripe160
	5.加版本
	6.sha256
	7.sha256
	8.后四位拼接到第5步之后
	9.base58编码
	*/
	//char* pubStr = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6";
	//char* pubStr = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";

	char step3[100] = { 0 };
	//char* step3 =(char*) malloc(1024);
	raHashSha256(pubStr, strlen(pubStr) / 2, step3);


	char Ripe160_step4[100] = { 0 };
	raHashRipe160(step3, strlen(step3) / 2, Ripe160_step4);

	char version_step5[100] = { 0 };
	sprintf(version_step5, "00%s", Ripe160_step4);

	char step6[100] = { 0 };
	raHashSha256(version_step5, strlen(version_step5) / 2, step6);

	char step7[100] = { 0 };

	raHashSha256(step6, strlen(step6) / 2, step7);

	char step8[100] = { 0 };
	char last4[10] = { 0 };
	//strncpy(last4, step7+ strlen(step7)-8, 8); 
	strncpy(last4, step7, 8);
	sprintf(step8, "%s%s", version_step5, last4);


	string hex_string = step8;

	//const char* step9 =  base58encode(hex_string).c_str();  //c_str()
	char step9[100] = { 0 };
	sprintf(step9, "%s", base58encode(hex_string).c_str());
	//strcpy(addrStr, step9);
	strcpy(addrStr, step9);

}

void getPubBase(char* priStr, char* baseG, char* pubStr) {

	int ret;	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* bn_n = BN_new();
	ret = BN_hex2bn(&bn_n, priStr);
	EC_POINT* ec_r = EC_POINT_new(g_curve_params->group);

	//EC_POINT* EC_POINT_hex2point(const EC_GROUP * group, const char* hex,
	//	EC_POINT * p, BN_CTX * ctx);

	EC_POINT* ec_base = EC_POINT_new(g_curve_params->group);
	EC_POINT_hex2point(g_curve_params->group, baseG, ec_base, ctx);



	//Q0 = k0 * P
	ret = EC_POINT_mul(g_curve_params->group, ec_r, NULL, ec_base, bn_n, ctx);
	//ret = EC_POINT_mul(g_curve_params->group, ec_r, NULL, g_curve_params->G, bn_n, ctx);

	char* result_invert = EC_POINT_point2hex(g_curve_params->group, ec_r, POINT_CONVERSION_COMPRESSED, ctx);
	//cout << result_invert << endl;
	strcpy(pubStr, result_invert);


	BN_CTX_free(ctx);
	BN_free(bn_n);
	EC_POINT_free(ec_r);
	EC_POINT_free(ec_base);
	OPENSSL_free(result_invert);




}

void getPubBaseQ_mp(char* Q_str,char*mp_str,char*pubStr){

int ret;	BN_CTX* ctx = BN_CTX_new();

	EC_POINT* ec_r = EC_POINT_new(g_curve_params->group);

	//EC_POINT* EC_POINT_hex2point(const EC_GROUP * group, const char* hex,
	//	EC_POINT * p, BN_CTX * ctx);

	EC_POINT* Q = EC_POINT_new(g_curve_params->group);
	EC_POINT* mp = EC_POINT_new(g_curve_params->group);
	EC_POINT_hex2point(g_curve_params->group, Q_str, Q, ctx);
	EC_POINT_hex2point(g_curve_params->group, mp_str, mp, ctx);



 // inverse of the supplied point a
 //        int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);
// 		a+b=r		
 // int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
 //                         const EC_POINT *b, BN_CTX *ctx);

EC_POINT_invert(g_curve_params->group, mp, ctx);
EC_POINT_add(g_curve_params->group,ec_r, Q,mp, ctx);

	char* result_invert = EC_POINT_point2hex(g_curve_params->group, ec_r, POINT_CONVERSION_COMPRESSED, ctx);
	char* mp_inverse = EC_POINT_point2hex(g_curve_params->group, mp, POINT_CONVERSION_COMPRESSED, ctx);
	char* Q_temp = EC_POINT_point2hex(g_curve_params->group, Q, POINT_CONVERSION_COMPRESSED, ctx);

	// cout<<"mp origin: "<<mp_str<<endl;
	// cout<<"mp_inverse: "<<mp_inverse<<endl;
	// cout<<"Q before: "<<Q_str<<endl;
	// cout<<"Q after: "<<Q_temp<<endl;

	//cout << result_invert << endl;
	strcpy(pubStr, result_invert);


	BN_CTX_free(ctx);
	
	EC_POINT_free(ec_r);
	EC_POINT_free(Q);
	EC_POINT_free(mp);
	
	OPENSSL_free(result_invert);
	OPENSSL_free(mp_inverse);
	OPENSSL_free(Q_temp);




}
void getPub(char* priStr, char* pubStr) {

	int ret;	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* bn_n = BN_new();
	ret = BN_hex2bn(&bn_n, priStr);
	EC_POINT* ec_r = EC_POINT_new(g_curve_params->group);


	//Q0 = k0 * P
	ret = EC_POINT_mul(g_curve_params->group, ec_r, NULL, g_curve_params->G, bn_n, ctx);

	char* result_invert = EC_POINT_point2hex(g_curve_params->group, ec_r, POINT_CONVERSION_COMPRESSED, ctx);
	//cout << result_invert << endl;
	strcpy(pubStr, result_invert);


	BN_CTX_free(ctx);
	BN_free(bn_n);
	EC_POINT_free(ec_r);
	OPENSSL_free(result_invert);




}
void addBn(char* a, char* b, char* r) {
	int ret;	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* bn_a = BN_new();
	BIGNUM* bn_b = BN_new();
	BIGNUM* bn_r = BN_new();
	ret = BN_hex2bn(&bn_a, a);
	ret = BN_hex2bn(&bn_b, b);
	ret = BN_hex2bn(&bn_r, r);
	ret = BN_add(bn_r, bn_a, bn_b);
	//char* BN_bn2hex(const BIGNUM * a);

	char* res = BN_bn2hex(bn_r);
	//BN_add(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);

	strcpy(r, res);



	BN_CTX_free(ctx);
	BN_free(bn_a);
	BN_free(bn_b);
	BN_free(bn_r);

	OPENSSL_free(res);




}
void findAddr() {
	//char* startX = "f99d00000000";
	char startX[100] = { 0 };
	//cout << "startX f99d000000000000 (f99d 0000 ,0000 0000)" << endl;
	cout << "startX 0000000000000000 (f99d 0000 ,0000 0000)" << endl;
	cin >> startX;
	//LONG_MAX
		//ULONG_MAX
	unsigned long index = 0;
	unsigned long count = ULONG_MAX; //0xffff ffffUL
	//unsigned int count = UINT_MAX;


	while (true)
	{
		if (index > count)
		{
			break;
		}

		char indexStr[100] = { 0 };
		//sprintf(indexStr, "%lx | %lx",index,count);
		sprintf(indexStr, "%lx", index);
		//cout << indexStr << endl;

		//cout << index << "," << count << endl;
		//char* priStr = "f9a9013bd8be";
		char priStr[100] = { 0 };

		addBn(startX, indexStr, priStr);
		char pubStr[256] = { 0 };
		getPub(priStr, pubStr);
		char addrStr[256] = { 0 };

		genAddr2(pubStr, addrStr);


		cout << priStr << "|	" << addrStr << "|	" << indexStr << "|	" << pubStr << endl;
		if (strcmp(addrStr, "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN") == 0)
		{
			cout << "find addr:" << addrStr << endl;
			break;
		}
		index++;
	}
}


void findAddr2() {
	//char* startX = "f99d00000000";
	char startX[100] = { 0 };
	//cout << "startX f99d000000000000 (f99d 0000 ,0000 0000)" << endl;
	//cout << "startX 0000000000000000 (  f99cbdfb599ed010  ,0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 );startX" << endl;
	cout << "startX:" << endl;
	cin >> startX;
	cout << "baseG:" << endl;
	char baseG[100] = { 0 };
	cin >> baseG;

	//LONG_MAX
		//ULONG_MAX
	unsigned long index = 0;
	unsigned long count = ULONG_MAX; //0xffff ffffUL
	//unsigned int count = UINT_MAX;
	int isRandom = 0;
	cout << "is random 1(random) 0 (not random)" << endl;
	cin >> isRandom;
	// srand((unsigned)1);
	srand((unsigned)time(NULL));
	cout << "baseG: " << baseG << " ,isRandom:" << isRandom << ",startX:" << startX << endl;
	while (true)
	{
		if (index > count)
		{
			break;
		}

		char indexStr[100] = { 0 };
		//sprintf(indexStr, "%lx | %lx",index,count);
		sprintf(indexStr, "%lx", index);
		//cout << indexStr << endl;

		//cout << index << "," << count << endl;
		//char* priStr = "f9a9013bd8be";
		char priStr[100] = { 0 };
		if (isRandom == 0) {
			addBn(startX, indexStr, priStr);
		}
		else {
			// char* pubStr = (char*)malloc(100);
			genRandom(priStr);

			// cout<<priStr<<endl;
		}
		// addBn(startX, indexStr, priStr);
		char pubStr[256] = { 0 };
		//getPub(priStr, pubStr);
		//getPub(priStr, pubStr);
		getPubBase(priStr, baseG, pubStr);
		char addrStr[256] = { 0 };

		genAddr2(pubStr, addrStr);
		char flag[10] = { 0 };
		char pubX[100] = { 0 };

		strncpy(flag, pubStr, 2);
		strncpy(pubX, pubStr + 2, strlen(pubStr) - 2);

		char targetAddress[] = "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN";
		//		if (strncmp(addrStr,targetAddress,3) == 0)
		//		{
		//			cout << priStr << "|" << addrStr << "|" << flag << "|" << pubX << endl;
		//
		if (strcmp(addrStr, "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN") == 0)
		{
			cout << "find addr:" << addrStr << endl;
			break;
		}
		//		}
		cout << priStr << "|" << addrStr << "|" << flag << "|" << pubX << endl;
		//cout << priStr << "|" <<flag<<"|"<<pubX << endl;

		index++;
	}
}

void findAddr3() {
	//char* startX = "f99d00000000";
	char startX[100] = { 0 };
	//cout << "startX f99d000000000000 (f99d 0000 ,0000 0000)" << endl;
	cout << "startX 0000000000000000 (  f99cbdfb599ed010  ,0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 );startX" << endl;
	cout << "startX:" << endl;
	cin >> startX;
	cout << "baseG:" << endl;
	char baseG[100] = { 0 };
	cin >> baseG;

	//LONG_MAX
		//ULONG_MAX
	unsigned long index = 0;
	unsigned long count = ULONG_MAX; //0xffff ffffUL
	//unsigned int count = UINT_MAX;
	int isRandom = 0;
	cout << "is random 1(random) 0 (not random)" << endl;
	cin >> isRandom;
	// srand((unsigned)1);
	srand((unsigned)time(NULL));
	cout << "baseG: " << baseG << " ,isRandom:" << isRandom << ",startX:" << startX << endl;
	while (true)
	{
		if (index > count)
		{
			break;
		}

		char indexStr[100] = { 0 };
		//sprintf(indexStr, "%lx | %lx",index,count);
		sprintf(indexStr, "%lx", index);
		//cout << indexStr << endl;

		//cout << index << "," << count << endl;
		//char* priStr = "f9a9013bd8be";
		char priStr[100] = { 0 };
		if (isRandom == 0) {
			addBn(startX, indexStr, priStr);
		}
		else {
			// char* pubStr = (char*)malloc(100);
			genRandom(priStr);

			// cout<<priStr<<endl;
		}
		// addBn(startX, indexStr, priStr);
		char pubStr[256] = { 0 };
		//getPub(priStr, pubStr);
		//getPub(priStr, pubStr);
		getPubBase(priStr, baseG, pubStr);


		//char addrStr[256] = { 0 };
		//genAddr2(pubStr, addrStr);



		char flag[10] = { 0 };
		char pubX[100] = { 0 };

		strncpy(flag, pubStr, 2);
		strncpy(pubX, pubStr + 2, strlen(pubStr) - 2);

		char targetAddress[] = "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN";
		//		if (strncmp(addrStr,targetAddress,3) == 0)
		//		{
		//			cout << priStr << "|" << addrStr << "|" << flag << "|" << pubX << endl;
		//
		/*if (strcmp(addrStr, "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN") == 0)
		{
			cout << "find addr:" << addrStr << endl;
			break;
		}*/
		//		}
		//cout << priStr << "|" << addrStr << "|" << flag << "|" << pubX << endl;
		//cout << priStr << "|" <<flag<<"|"<<pubX << endl;
		//strncmp()
		//int len_cmp = 4;
		int len_cmp = 2;
		if (strncmp(pubX,"0000000000000000000000000000000000000000",len_cmp) == 0) {
			cout << priStr << " " << pubStr << endl;

		}
		index++;
	}
}

void gen_power_mod(char* a,char* k,char* n,char* out_pri) {
	//a**i mod n


	int ret;	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* bn_a = BN_new();
	BIGNUM* bn_k = BN_new();
	BIGNUM* bn_n = BN_new();
	BIGNUM* bn_r = BN_new();
	ret = BN_hex2bn(&bn_a, a);
	ret = BN_hex2bn(&bn_k, k);
	ret = BN_hex2bn(&bn_n, n);

	// a**p mod m 
	//BN_mod_exp(BIGNUM * r, BIGNUM * a, const BIGNUM * p,
	//	const BIGNUM * m, BN_CTX * ctx);

	ret = BN_mod_exp(bn_r, bn_a , bn_k ,
		bn_n,  ctx);


	//ret = BN_add(bn_r, bn_a, bn_b);
	//char* BN_bn2hex(const BIGNUM * a);

	char* res = BN_bn2hex(bn_r);
	//BN_add(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);

	strcpy(out_pri, res);



	BN_CTX_free(ctx);
	BN_free(bn_a);
	BN_free(bn_k);
	BN_free(bn_n);
	BN_free(bn_r);

	OPENSSL_free(res);




}
void findAddr4() {
	//char* startX = "f99d00000000";
	//const char* a_str = "73aa7c979bb15317727fe8c587825ba6c3422c67cca28c01ac50b2ca1b7ce93b";
	const char* n_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	
	char startX[100] = { 0 };
	//cout << "startX f99d000000000000 (f99d 0000 ,0000 0000)" << endl;
	cout << "startX 0000000000000000 (  f99cbdfb599ed010  ,0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 );startX" << endl;
	cout << "startX:" << endl;
	cin >> startX;
	cout << "baseG:" << endl;
	char baseG[100] = { 0 };
	cin >> baseG;

	cout << "a_str: 107361793816595537 73aa7c979bb15317727fe8c587825ba6c3422c67cca28c01ac50b2ca1b7ce93b ,174723607534414371449  779dd6e5189c2695ec5ae789d9bc9fede2b7fd80d66019a65e4a568dbec5a805 ,341948486974166000522343609283189  68450b6d617318cf99cb3172e1682b7ee924dfafad77120055ee9a91fee78e1" << endl;
	char a_str[100] = { 0 };
	cin >> a_str;
	int len_cmp = 4;
	cout << "len_cmp 过滤长度：默认4" << endl ;
	cin >> len_cmp;


	//LONG_MAX
		//ULONG_MAX
	unsigned long index = 0;
	//unsigned long count = ULONG_MAX; //0xffff ffffUL
	unsigned long count = ULLONG_MAX; //0xffffffffffffffffu
	//unsigned int count = UINT_MAX;
	int isRandom = 0;
	cout << "is random 1(random) 0 (not random)" << endl;
	cin >> isRandom;
	// srand((unsigned)1);
	srand((unsigned)time(NULL));


	cout << "baseG: " << baseG <<" a_str 基数pri=a**k mod p "<< a_str  <<" len_cmp: "<< len_cmp << " ,isRandom:" << isRandom << ",startX:" << startX << endl;


	while (true)
	{
		if (index > count)
		{
			break;
		}

		char indexStr[100] = { 0 };
		//sprintf(indexStr, "%lx | %lx",index,count);
		sprintf(indexStr, "%lx", index);
		//cout << indexStr << endl;

		//cout << index << "," << count << endl;
		//char* priStr = "f9a9013bd8be";
		char priStr[100] = { 0 };

		//------------ 根据不同逻辑选择 k
		if (isRandom == 0) {
			addBn(startX, indexStr, priStr);
		}
		else {
			// char* pubStr = (char*)malloc(100);
			//genRandom(priStr);


			gen_power_mod((char*)a_str , (char*)indexStr , (char*)n_str, (char*)priStr);


			// cout<<priStr<<endl;
		}








		// addBn(startX, indexStr, priStr);
		char pubStr[256] = { 0 };
		//getPub(priStr, pubStr);
		//getPub(priStr, pubStr);




		getPubBase(priStr, baseG, pubStr);

		  
		char flag[10] = { 0 };
		char pubX[100] = { 0 };

		strncpy(flag, pubStr, 2);
		strncpy(pubX, pubStr + 2, strlen(pubStr) - 2);

		char targetAddress[] = "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN"; 
		
		//int len_cmp = 2;


		//cout << indexStr <<" " << priStr << " " << pubStr << endl;



		if (strncmp(pubX, "0000000000000000000000000000000000000000", len_cmp) == 0) {
			//cout << priStr << " " << pubStr << endl;
			cout << indexStr << " " << priStr << " " << pubStr << endl;

		}
		index++;
	}
}


bool call1(void)
{
	//string str = "0123456789abcdefghijklmn";
	string str = "00010966776006953D5567439E5E39F86A0D273BEE";

	unsigned char result[32];
	SHA256((const unsigned char*)str.c_str(), str.length(), result);

	for (int i = 0; i < 32; i++) {
		printf("%02x ", result[i]);
	}
	cout << endl;
	return true;
}
std::string base58encode(const std::string& hexstring)
{
	std::string result = "";
	BN_CTX* bnctx = BN_CTX_new();
	BIGNUM* bn = BN_new();
	BIGNUM* bn0 = BN_new();
	BIGNUM* bn58 = BN_new();
	BIGNUM* dv = BN_new();
	BIGNUM* rem = BN_new();

	BN_hex2bn(&bn, hexstring.c_str());
	//printf("bn:%s\n", BN_bn2dec(bn));
	BN_hex2bn(&bn58, "3a");//58
	BN_hex2bn(&bn0, "0");

	while (BN_cmp(bn, bn0) > 0) {
		BN_div(dv, rem, bn, bn58, bnctx);
		BN_copy(bn, dv);
		//printf("dv: %s\n", BN_bn2dec(dv));
		//printf("rem:%s\n", BN_bn2dec(rem));
		char base58char = BASE58TABLE[BN_get_word(rem)];
		result += base58char;
	}

	std::string::iterator pbegin = result.begin();
	std::string::iterator pend = result.end();
	while (pbegin < pend) {
		char c = *pbegin;
		*(pbegin++) = *(--pend);
		*pend = c;
	}
	result.insert(0, 1, '1');



	BN_CTX_free(bnctx);
	BN_free(bn);
	BN_free(bn0);
	BN_free(bn58);
	BN_free(dv);
	BN_free(rem);



	return result;
}
void testAddress() {

	//std::string hex_string = "00010966776006953D5567439E5E39F86A0D273BEED61967F6";
	std::string hex_string = "00010966776006953D5567439E5E39F86A0D273BEED61967F6";
	cout << base58encode(hex_string).c_str() << endl;
}

void hashSM3(unsigned char* puchMM, size_t uiMMLen, unsigned char* outEChar, unsigned  int* uiDigestLen) {
	//const EVP_MD* EVP_sha256(void);
	//const EVP_MD* EVP_ripemd160(void);

	const EVP_MD* mdType = EVP_sm3();
	EVP_MD_CTX* ctx_evp = EVP_MD_CTX_new();
	//         EVP_MD_CTX_init(ctx_evp);
	EVP_DigestInit_ex(ctx_evp, mdType, NULL);
	EVP_DigestUpdate(ctx_evp, puchMM, uiMMLen);
	EVP_DigestFinal_ex(ctx_evp, outEChar, uiDigestLen);
	EVP_MD_CTX_free(ctx_evp);


}


void raHashSM3(char* plain, int len, char* hash) {

	//    unsigned char *puchMM = malloc(sizeof(len+1));
	unsigned char* puchMM = (unsigned char*)malloc(len + 1);

	memcpy(puchMM, plain, len);
	unsigned char* outEchar = (unsigned char*)malloc(32 + 1);
	unsigned int outLen = 32;

	hashSM3(puchMM, len, outEchar, &outLen);

	char* outHash = (char*)malloc(64 + 1);
	memset(outHash, 0, 64 + 1);
	//    memcpy(outHash, outEchar, outLen);
	convertUnCharToStr(outHash, outEchar, outLen);
	strcpy(hash, outHash);

	//    unsigned char tmp[33] = {0};
	//    convertStrToUnChar(hash, tmp);

	//清理敏感数据
	memset(puchMM, 0, len);
	strcpy(plain, "");

	free(puchMM);
	free(outEchar);
	free(outHash);

}
int  setECC(BN_CTX** ctx, EC_GROUP** group, BIGNUM** p, BIGNUM** a, BIGNUM** b, EC_POINT** outG, BIGNUM** outOrder) {


	/*
						###############  开发环境参数

	BN_hex2bn(p, "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3");
	BN_hex2bn(a, "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498");
	BN_hex2bn(b, "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A");
	BN_hex2bn(&order, "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7");
	BN_hex2bn(&xg, "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D");
	BN_hex2bn(&yg, "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2");



	*/

	/*
						#################  生产环境参数

p=FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a=FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b=28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93

*group = EC_GROUP_new_curve_GFp(*p, *a, *b, *ctx);
	//设置G点
	EC_POINT* G = EC_POINT_new(*group);

	BIGNUM* xg = BN_new();
	BIGNUM* yg = BN_new();
	BIGNUM* order = BN_new();


n=FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx=32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy=BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0



	BN_hex2bn(p, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
	BN_hex2bn(a, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
	BN_hex2bn(b, "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");

	*group = EC_GROUP_new_curve_GFp(*p, *a, *b, *ctx);
	//设置G点
	EC_POINT* G = EC_POINT_new(*group);

	BIGNUM* xg = BN_new();
	BIGNUM* yg = BN_new();
	BIGNUM* order = BN_new();

	BN_hex2bn(&order, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
	BN_hex2bn(&xg, "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
	BN_hex2bn(&yg, "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");


	*/

	/*
	Recommended Parameters secp256k1

	p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
The curve E: y2 = x3 + ax + b over Fp is defined by:

a = 0000000000000000000000000000000000000000000000000000000000000000
b = 0000000000000000000000000000000000000000000000000000000000000007

G = 04
79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

h = 01


 y2 = x3 + 130x + 565 defined over F719.

 a = 130  ,82
 b = 565, 235
 p=719,	2cf
 n = 699, 2bb


 P = (107, 443) and that Q = (608, 427),
  P = (6b, 1bb) and that Q = (260, 1ab),


	*/

	//BN_hex2bn(p, "2cf");
	//BN_hex2bn(a, "82");
	//BN_hex2bn(b, "235");

	//*group = EC_GROUP_new_curve_GFp(*p, *a, *b, *ctx);
	////设置G点
	//EC_POINT* G = EC_POINT_new(*group);

	//BIGNUM* xg = BN_new();
	//BIGNUM* yg = BN_new();
	//BIGNUM* order = BN_new();

	//BN_hex2bn(&order, "2bb");
	//BN_hex2bn(&xg, "6b");
	//BN_hex2bn(&yg, "1bb");



	BN_hex2bn(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	BN_hex2bn(a, "0000000000000000000000000000000000000000000000000000000000000000");
	BN_hex2bn(b, "0000000000000000000000000000000000000000000000000000000000000007");

	*group = EC_GROUP_new_curve_GFp(*p, *a, *b, *ctx);
	//设置G点
	EC_POINT* G = EC_POINT_new(*group);

	BIGNUM* xg = BN_new();
	BIGNUM* yg = BN_new();
	BIGNUM* order = BN_new();

	BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");


	BN_hex2bn(&xg, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	BN_hex2bn(&yg, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");



	char gx[256] = { 0 };
	char gy[256] = { 0 };
	//cout << "输入gx,gy" << endl;
	//cin >> gx;
	//cin >> gy;
	//cout << "gx:" << gx << ",gy:" << gy << endl;
	//BN_hex2bn(&xg, gx);
	//BN_hex2bn(&yg, gy);

	int    iRet = EC_POINT_set_affine_coordinates(*group, G, xg, yg, *ctx);

	BIGNUM* cofactor = BN_new();
	BN_hex2bn(&cofactor, "1");

	iRet = EC_GROUP_set_generator(*group, G, order, cofactor);
	*outG = EC_POINT_new(*group);



	EC_POINT_copy(*outG, G);
	BN_copy(*outOrder, order);

	EC_POINT_free(G);
	BN_free(xg);
	BN_free(yg);
	BN_free(order);
	BN_free(cofactor);





	return iRet;

}

int  setECC3(BN_CTX** ctx, EC_GROUP** group, BIGNUM** p, BIGNUM** a, BIGNUM** b, EC_POINT** outG, BIGNUM** outOrder) {

	cout << "P:" << endl;
	int p_dec, a_dec, b_dec, gx_dec, gy_dec, order_dec;

	p_dec = 43;
	a_dec = 1;
	b_dec = 1;
	gx_dec = 43;
	gy_dec = 33;
	order_dec = 34;
	cin >> p_dec;
	cout << "a:" << endl;
	cin >> a_dec;
	cout << "b:" << endl;
	cin >> b_dec;
	cout << "x:" << endl;
	cin >> gx_dec;
	cout << "y:" << endl;
	cin >> gy_dec;
	cout << "order:" << endl;
	cin >> order_dec;

	char temp[256] = { 0 };
	sprintf(temp, "%x", p_dec);

	BN_hex2bn(p, temp);
	cout << "P:" << temp << endl;
	memset(temp, 0, 256);
	sprintf(temp, "%x", a_dec);
	BN_hex2bn(a, temp);
	cout << "a:" << temp << endl;
	memset(temp, 0, 256);
	sprintf(temp, "%x", b_dec);
	BN_hex2bn(b, temp);
	cout << "b:" << temp << endl;
	memset(temp, 0, 256);
	//BN_hex2bn(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	//BN_hex2bn(a, "0000000000000000000000000000000000000000000000000000000000000000");
	//BN_hex2bn(b, "0000000000000000000000000000000000000000000000000000000000000007");

	*group = EC_GROUP_new_curve_GFp(*p, *a, *b, *ctx);
	//设置G点
	EC_POINT* G = EC_POINT_new(*group);

	BIGNUM* xg = BN_new();
	BIGNUM* yg = BN_new();
	BIGNUM* order = BN_new();

	sprintf(temp, "%x", order_dec);
	BN_hex2bn(&order, temp);
	cout << "order:" << temp << endl;
	memset(temp, 0, 256);

	sprintf(temp, "%x", gx_dec);
	BN_hex2bn(&xg, temp);
	cout << "x:" << temp << endl;
	memset(temp, 0, 256);
	sprintf(temp, "%x", gy_dec);

	BN_hex2bn(&yg, temp);
	cout << "y:" << temp << endl;
	memset(temp, 0, 256);

	//exit(0);

	int    iRet = EC_POINT_set_affine_coordinates(*group, G, xg, yg, *ctx);

	BIGNUM* cofactor = BN_new();
	BN_hex2bn(&cofactor, "1");

	iRet = EC_GROUP_set_generator(*group, G, order, cofactor);
	*outG = EC_POINT_new(*group);



	EC_POINT_copy(*outG, G);
	BN_copy(*outOrder, order);

	EC_POINT_free(G);
	BN_free(xg);
	BN_free(yg);
	BN_free(order);
	BN_free(cofactor);





	return iRet;

}

int  setECC4(BN_CTX** ctx, EC_GROUP** group, BIGNUM** p, BIGNUM** a, BIGNUM** b, EC_POINT** outG, BIGNUM** outOrder) {

	cout << "P:" << endl;
	int p_dec, a_dec, b_dec, gx_dec, gy_dec, order_dec;
	cin >> p_dec;
	cout << "a:" << endl;
	cin >> a_dec;
	cout << "b:" << endl;
	cin >> b_dec;
	cout << "x:" << endl;
	cin >> gx_dec;
	cout << "y:" << endl;
	cin >> gy_dec;
	cout << "order:" << endl;
	cin >> order_dec;

	char temp[256] = { 0 };
	sprintf(temp, "%x", p_dec);

	BN_hex2bn(p, temp);
	cout << "P:" << temp << endl;
	memset(temp, 0, 256);
	sprintf(temp, "%x", a_dec);
	BN_hex2bn(a, temp);
	cout << "a:" << temp << endl;
	memset(temp, 0, 256);
	sprintf(temp, "%x", b_dec);
	BN_hex2bn(b, temp);
	cout << "b:" << temp << endl;
	memset(temp, 0, 256);
	//BN_hex2bn(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	//BN_hex2bn(a, "0000000000000000000000000000000000000000000000000000000000000000");
	//BN_hex2bn(b, "0000000000000000000000000000000000000000000000000000000000000007");

	*group = EC_GROUP_new_curve_GFp(*p, *a, *b, *ctx);
	//设置G点
	EC_POINT* G = EC_POINT_new(*group);

	BIGNUM* xg = BN_new();
	BIGNUM* yg = BN_new();
	BIGNUM* order = BN_new();

	sprintf(temp, "%x", order_dec);
	BN_hex2bn(&order, temp);
	cout << "order:" << temp << endl;
	memset(temp, 0, 256);

	sprintf(temp, "%x", gx_dec);
	BN_hex2bn(&xg, temp);
	cout << "x:" << temp << endl;
	memset(temp, 0, 256);
	sprintf(temp, "%x", gy_dec);

	BN_hex2bn(&yg, temp);
	cout << "y:" << temp << endl;
	memset(temp, 0, 256);

	//exit(0);

	int    iRet = EC_POINT_set_affine_coordinates(*group, G, xg, yg, *ctx);

	BIGNUM* cofactor = BN_new();
	BN_hex2bn(&cofactor, "1");

	iRet = EC_GROUP_set_generator(*group, G, order, cofactor);
	*outG = EC_POINT_new(*group);



	EC_POINT_copy(*outG, G);
	BN_copy(*outOrder, order);

	EC_POINT_free(G);
	BN_free(xg);
	BN_free(yg);
	BN_free(order);
	BN_free(cofactor);





	return iRet;

}

//int  setECC(BN_CTX** ctx, EC_GROUP** group, BIGNUM** p, BIGNUM** a, BIGNUM** b, EC_POINT** outG, BIGNUM** outOrder) {
//
//	setECC1(ctx, group, p, a, b, outG,outOrder);
//
//}
void RAPSIUtilOpenSSL::setEcc() {
	if (g_curve_params != NULL) {
		printf("setEcc 已初始化\n");
		return;
	}

	BN_CTX* ctx = BN_CTX_new();
	//    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
	EC_GROUP* group;// = EC_GROUP_new_by_curve_name(NID_sm2);


	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();
	//    EC_POINT *G = EC_POINT_new(group);
	EC_POINT* G;//= EC_POINT_new(group);

	BIGNUM* order = BN_new();
	setECC(&ctx, &group, &p, &a, &b, &G, &order);

	g_curve_params = (CurveParams*)malloc(sizeof(CurveParams));
	g_curve_params->p = p;
	g_curve_params->a = a;
	g_curve_params->b = b;
	g_curve_params->group = group;
	g_curve_params->G = G;
	g_curve_params->order = order;

	BN_CTX_free(ctx);


}


void RAPSIUtilOpenSSL::sm3Hash(char* data, char* hash) {
	raHashSM3(data, (int)strlen(data), hash);

}
void RAPSIUtilOpenSSL::getInverseRA(char* ra, char* ra_1) {

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* rb = BN_new();
	BIGNUM* rb_1 = BN_new();

	BN_hex2bn(&rb, ra);
	BN_mod_inverse(rb_1, rb, g_curve_params->order, ctx);
	char* resutl = BN_bn2hex(rb_1);
	strcpy(ra_1, resutl);


	strcpy(ra, "");

	BN_CTX_free(ctx);
	BN_free(rb);
	BN_free(rb_1);
	OPENSSL_free(resutl);


}
void RAPSIUtilOpenSSL::pointBlindRA(char* point, char* ra, char* blindPoint) {

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* n = BN_new();
	int ret = BN_hex2bn(&n, ra);

	EC_POINT* pointa = EC_POINT_new(g_curve_params->group);
	EC_POINT* blind_pointa = EC_POINT_new(g_curve_params->group);

	EC_POINT_hex2point(g_curve_params->group, point, pointa, ctx);


	ret = EC_POINT_mul(g_curve_params->group, blind_pointa, NULL, pointa, n, ctx);
	if (ret == 1) {
		//        printf("EC_POINT_mul success \n");


		//        RAPonintCompressType
		char* result = EC_POINT_point2hex(g_curve_params->group, blind_pointa, POINT_CONVERSION_UNCOMPRESSED, ctx);
		strcpy(blindPoint, result);

		OPENSSL_free(result);
	}

	strcpy(point, "");
	strcpy(ra, "");

	BN_CTX_free(ctx);
	BN_free(n);
	EC_POINT_free(pointa);
	EC_POINT_free(blind_pointa);



}

void ComputeYSquare(const BIGNUM* x, CurveParams* curve_params_, BIGNUM** out_y2) {
	//    计算 y^2 = x^3 + a*x + b

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* x3 = BN_new();
	BIGNUM* x1 = BN_new();
	//    BIGNUM *x0 = BN_new();
	BIGNUM* x0;
	BIGNUM* y2 = BN_new();
	BIGNUM* tmp = BN_new();

	BN_hex2bn(&tmp, "3");

	int ret = BN_exp(x3, x, tmp, ctx);
	if (ret == 0) {
		printf("error \n");
	}
	ret = BN_mul(x1, x, curve_params_->a, ctx);
	x0 = curve_params_->b;
	ret = BN_add(y2, x3, x1);
	ret = BN_add(y2, y2, x0);

	BIGNUM* result = BN_new();
	BN_mod(result, y2, curve_params_->p, ctx);
	BN_copy(*out_y2, result);

	BN_free(x3);
	BN_free(x1);
	//    BN_free(x0);
	BN_free(y2);
	BN_free(tmp);
	BN_free(result);
	BN_CTX_free(ctx);

}
int isSqure(BIGNUM* y2, CurveParams* curve_params) {
	//    判断y2是否有平方根， y2 exp ((p - 1)/2) mod p == 1
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* sub1 = BN_new();
	BIGNUM* subRes = BN_new();
	BN_hex2bn(&sub1, "1");
	BN_sub(subRes, curve_params->p, sub1);

	BIGNUM* div1 = BN_new();
	BIGNUM* divRes = BN_new();
	BN_hex2bn(&div1, "2");
	BN_div(divRes, NULL, subRes, div1, ctx);



	BIGNUM* expRes = BN_new();
	//    BN_exp(expRes, y2, divRes, ctx);
	int ret = BN_mod_exp(expRes, y2, divRes, curve_params->p, ctx);
	ret = BN_is_one(expRes);


	BN_CTX_free(ctx);
	BN_free(sub1);
	BN_free(subRes);
	BN_free(div1);
	BN_free(divRes);
	BN_free(expRes);



	return ret;

}

void makeList() {

	cout << "makeList" << endl;


	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* n = BN_new();
	const char* ra = "1";


	int ret;

	char blindPoint[1024] = { 0 };
	EC_POINT* pointa = EC_POINT_new(g_curve_params->group);
	EC_POINT* blind_pointa = EC_POINT_new(g_curve_params->group);

	//EC_POINT_hex2point(g_curve_params->group, point, pointa, ctx);



	int i = 0;
	int count = 1000;
	while (true)
	{
		char temp[256] = { 0 };
		sprintf(temp, "%x", i);

		ret = BN_hex2bn(&n, temp);
		ret = EC_POINT_mul(g_curve_params->group, blind_pointa, NULL, g_curve_params->G, n, ctx);
		if (ret == 1) {
			//POINT_CONVERSION_UNCOMPRESSED   POINT_CONVERSION_COMPRESSED  POINT_CONVERSION_HYBRID
			char* result = EC_POINT_point2hex(g_curve_params->group, blind_pointa, POINT_CONVERSION_UNCOMPRESSED, ctx);
			cout << temp << "	|	" << result << endl;
			OPENSSL_free(result);



		}
		i++;
		if (i >= count)
		{
			break;

		}

	}


	BN_CTX_free(ctx);
	BN_free(n);
	EC_POINT_free(pointa);
	EC_POINT_free(blind_pointa);


}
void mulityPoint(char* factor, char* point, char** ourRes) {
	//char temp[256] = "1b";
	char* temp = factor;



	BIGNUM* n = BN_new();

	BN_CTX* ctx = BN_CTX_new();

	int ret;
	EC_POINT* blind_pointa = EC_POINT_new(g_curve_params->group);
	EC_POINT* pointPP = EC_POINT_new(g_curve_params->group);
	EC_POINT_hex2point(g_curve_params->group, point, pointPP, ctx);
	ret = BN_hex2bn(&n, temp);


	ret = EC_POINT_mul(g_curve_params->group, blind_pointa, NULL, pointPP, n, ctx);
	if (ret == 1) {
		//POINT_CONVERSION_UNCOMPRESSED   POINT_CONVERSION_COMPRESSED  POINT_CONVERSION_HYBRID
		char* result = EC_POINT_point2hex(g_curve_params->group, blind_pointa, POINT_CONVERSION_COMPRESSED, ctx);
		//cout << temp << "	|	" << result << endl;
		strcpy(*ourRes, result);
		OPENSSL_free(result);



	}


	BN_CTX_free(ctx);
	BN_free(n);
	EC_POINT_free(blind_pointa);
	EC_POINT_free(pointPP);

}

void negativePoint(char* Q, char* point, char** outRes) {
	//int EC_POINT_invert(const EC_GROUP * group, EC_POINT * a, BN_CTX * ctx);

	//char* point = "04027B0169";
	//char* Q = "04026001AB";
	//
	BN_CTX* ctx = BN_CTX_new();
	EC_POINT* inputPoint = EC_POINT_new(g_curve_params->group);
	EC_POINT* addPoint = EC_POINT_new(g_curve_params->group);
	EC_POINT* QPoint = EC_POINT_new(g_curve_params->group);
	EC_POINT* inputPoint_temp = EC_POINT_new(g_curve_params->group);


	EC_POINT_hex2point(g_curve_params->group, point, inputPoint, ctx);
	EC_POINT_hex2point(g_curve_params->group, point, inputPoint_temp, ctx);
	EC_POINT_hex2point(g_curve_params->group, Q, QPoint, ctx);


	int ret;
	//-mP
	ret = EC_POINT_invert(g_curve_params->group, inputPoint, ctx);
	if (ret == 1)
	{
		//-mP
		char* result = EC_POINT_point2hex(g_curve_params->group, inputPoint, POINT_CONVERSION_UNCOMPRESSED, ctx);
		//cout <<point<<"	|	"<< result << endl;
		OPENSSL_free(result);


		/*int EC_POINT_add(const EC_GROUP * group, EC_POINT * r, const EC_POINT * a,
			const EC_POINT * b, BN_CTX * ctx);*/
			//ret=EC_POINT_add(g_curve_params->group, addPoint, inputPoint, QPoint,ctx);
			//Q-mP
		ret = EC_POINT_add(g_curve_params->group, addPoint, QPoint, inputPoint, ctx);
		if (ret == 1)
		{

			char* result_add = EC_POINT_point2hex(g_curve_params->group, addPoint, POINT_CONVERSION_UNCOMPRESSED, ctx);
			//cout << "add:" << result_add << endl;

			strcpy(*outRes, result_add);
			OPENSSL_free(result_add);

		}


	}

	BN_CTX_free(ctx);


	EC_POINT_free(inputPoint);
	EC_POINT_free(addPoint);
	EC_POINT_free(QPoint);
	EC_POINT_free(inputPoint_temp);

}

void negativePoint(char* Q, char* point, char** outRes, char** negPoint) {
	//int EC_POINT_invert(const EC_GROUP * group, EC_POINT * a, BN_CTX * ctx);

	//char* point = "04027B0169";
	//char* Q = "04026001AB";
	//
	BN_CTX* ctx = BN_CTX_new();
	EC_POINT* inputPoint = EC_POINT_new(g_curve_params->group);
	EC_POINT* addPoint = EC_POINT_new(g_curve_params->group);
	EC_POINT* QPoint = EC_POINT_new(g_curve_params->group);
	EC_POINT* inputPoint_temp = EC_POINT_new(g_curve_params->group);


	EC_POINT_hex2point(g_curve_params->group, point, inputPoint, ctx);
	EC_POINT_hex2point(g_curve_params->group, point, inputPoint_temp, ctx);
	EC_POINT_hex2point(g_curve_params->group, Q, QPoint, ctx);


	int ret;
	//-mP
	ret = EC_POINT_invert(g_curve_params->group, inputPoint, ctx);
	if (ret == 1)
	{
		//-mP
		char* result = EC_POINT_point2hex(g_curve_params->group, inputPoint, POINT_CONVERSION_COMPRESSED, ctx);
		//cout <<point<<"	|	"<< result << endl;
		strcpy(*negPoint, result);
		OPENSSL_free(result);


		/*int EC_POINT_add(const EC_GROUP * group, EC_POINT * r, const EC_POINT * a,
			const EC_POINT * b, BN_CTX * ctx);*/
			//ret=EC_POINT_add(g_curve_params->group, addPoint, inputPoint, QPoint,ctx);
			//Q-mP
		ret = EC_POINT_add(g_curve_params->group, addPoint, QPoint, inputPoint, ctx);
		if (ret == 1)
		{

			char* result_add = EC_POINT_point2hex(g_curve_params->group, addPoint, POINT_CONVERSION_COMPRESSED, ctx);
			//cout << "add:" << result_add << endl;

			strcpy(*outRes, result_add);
			OPENSSL_free(result_add);

		}


	}

	BN_CTX_free(ctx);


	EC_POINT_free(inputPoint);
	EC_POINT_free(addPoint);
	EC_POINT_free(QPoint);
	EC_POINT_free(inputPoint_temp);

}
void listNegative() {
	char* factor = "1b";
	char* pointFactor = "04006B01BB";
	//char outMulity[100] = { 0 };
	char* outMulity = (char*)malloc(100);
	mulityPoint(factor, pointFactor, (char**)&outMulity);

	//cout << factor << "	|" << pointFactor << " |" << outMulity << endl;


	int ret;
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* n = BN_new();
	EC_POINT* mP = EC_POINT_new(g_curve_params->group);
	EC_POINT* blind_pointa = EC_POINT_new(g_curve_params->group);
	EC_POINT_hex2point(g_curve_params->group, outMulity, mP, ctx);



	int i = 0;
	int count = 1000;
	while (true)
	{

		char temp[256] = { 0 };
		sprintf(temp, "%x", i);

		ret = BN_hex2bn(&n, temp);
		ret = EC_POINT_mul(g_curve_params->group, blind_pointa, NULL, mP, n, ctx);
		if (ret == 1) {
			//mP   ，target = Q - i*mP


			//POINT_CONVERSION_UNCOMPRESSED   POINT_CONVERSION_COMPRESSED  POINT_CONVERSION_HYBRID
			char* result = EC_POINT_point2hex(g_curve_params->group, blind_pointa, POINT_CONVERSION_COMPRESSED, ctx);
			//cout << temp << "	|	" << result << endl;

			char* QStr = "04026001AB";
			//char* baseStr = "04027B0169";
			char* baseStr = result;
			char* outNegRes = (char*)malloc(100);
			char* negPoint = (char*)malloc(100);
			EC_POINT* Q = EC_POINT_new(g_curve_params->group);
			EC_POINT_hex2point(g_curve_params->group, QStr, Q, ctx);
			EC_POINT* basePoint = EC_POINT_new(g_curve_params->group);
			EC_POINT_hex2point(g_curve_params->group, baseStr, basePoint, ctx);

			//i，target,i*mP,-i*mP
			//negativePoint(QStr, baseStr, &outNegRes);
			negativePoint(QStr, baseStr, &outNegRes, &negPoint);
			//cout << outNegRes << endl;

			cout << temp << "	|" << outNegRes << "	|" << result << "	|" << negPoint << endl;



			free(negPoint);
			free(outNegRes);
			OPENSSL_free(result);



		}
		i++;
		if (i >= count)
		{
			break;

		}



	}



	BN_CTX_free(ctx);
	BN_free(n);
	EC_POINT_free(mP);
	EC_POINT_free(blind_pointa);


}


void getReverse(char* ra, char** ra_1) {

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* rb = BN_new();
	BIGNUM* rb_1 = BN_new();

	BN_hex2bn(&rb, ra);
	BIGNUM* ret = BN_mod_inverse(rb_1, rb, g_curve_params->order, ctx);

	char* temp = BN_bn2hex(g_curve_params->order);
	cout << temp << endl;
	if (ret == NULL)
	{
		cout << "inverse error\n" << endl;
	}
	char* resutl = BN_bn2hex(rb_1);
	cout << "resutl:" << resutl << endl;
	strcpy(*ra_1, resutl);

	BN_CTX_free(ctx);
	BN_free(rb);
	BN_free(rb_1);
	OPENSSL_free(resutl);


}

void testEDLP() {

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* n = BN_new();
	/*

	//makeList();
	//char* factor = "1b";
	//char* factor = "78";//120
	//char* factor = "5a";//90 = 9*10
	char* factor = "5b";//90 = 9*10
	char* factor_a = "9";//10
	char* factor_b = "a"; //10
	//char* factor_b = "c"; //12   次数没有逆元
	char* pointFactor = "04006B01BB";
	//char outMulity[100] = { 0 };
	char *outMulity = (char*)malloc(100);//Q=a*b
	char *outMulity_rb = (char*)malloc(100);//Q=a*b
	char *outMulity_a = (char*)malloc(100);
	char *outMulity_b = (char*)malloc(100);
	char *outMulity_b_b1 = (char*)malloc(100);
	char *outMulity_a_b = (char*)malloc(100);
	char *reverse_b = (char*)malloc(100);

	//static RAPSIUtil* m_util2;

	//m_util2 = new RAPSIUtilOpenSSL();

	getReverse(factor_b,&reverse_b);
	//m_util->data2Point(data, point);
	//m_util2->getInverseRA(factor_b, reverse_b);
	cout << "reverse_b:" << reverse_b << endl;

	mulityPoint(factor,pointFactor,(char**)&outMulity);//90
	mulityPoint(factor_a,pointFactor,(char**)&outMulity_a);//9
	mulityPoint(factor_b,pointFactor,(char**)&outMulity_b);//10
	mulityPoint(reverse_b, outMulity_b,(char**)&outMulity_b_b1);//10*-10
	mulityPoint(reverse_b, outMulity,(char**)&outMulity_rb);//90/10 = 9
	//5b=91 46=70 ,5b*46=18e2



	mulityPoint(factor_a,outMulity_b,(char**)&outMulity_a_b);
	//
	 cout <<"Q:"<<factor<<"	|"<<pointFactor<<" |" << outMulity << endl;
	cout <<"a:"<< factor_a <<"	|"<<pointFactor<<" |" << outMulity_a << endl;
	//cout <<"b:"<< factor_b<<"	|"<<pointFactor<<" |" << outMulity_b << endl;
	//cout <<"b:"<< factor_b<<"	|"<<pointFactor<<" |" << outMulity_b << endl;
	//cout <<"a*b:"<<"	|"<<pointFactor<<" |" << outMulity_rb << endl;

	cout << "b:" << factor_b << "	|" << pointFactor << " |" << outMulity_b << endl;
	cout << "b*b-1:" << reverse_b << "	|" << pointFactor << " |" << outMulity_b_b1 << endl;
	cout << "a*b:" << "	|" << pointFactor << " |" << outMulity_rb << endl;

	//void negativePoint(char* Q, char* point, char** outRes) {
	//	//int EC_POINT_invert(const EC_GROUP * group, EC_POINT * a, BN_CTX * ctx);

	//	//char* point = "04027B0169";
	//	//char* Q = "04026001AB";


	//listNegative();
	/*char* QStr = "04026001AB";
	char* baseStr = "04027B0169";
	char* outNegRes = (char*)malloc(100);
	EC_POINT* Q = EC_POINT_new(g_curve_params->group);
	EC_POINT_hex2point(g_curve_params->group, QStr, Q, ctx);
	EC_POINT* basePoint = EC_POINT_new(g_curve_params->group);
	EC_POINT_hex2point(g_curve_params->group, baseStr, basePoint, ctx);


	negativePoint(QStr, baseStr,&outNegRes);
	cout << outNegRes << endl;*/



	/*cout << "hello world" << endl;
	return;
	*/

	{
		int ret;
		BIGNUM* a = BN_new();
		BIGNUM* b = BN_new();
		BIGNUM* c_mod = BN_new();
		BIGNUM* c_div = BN_new();
		ret = BN_hex2bn(&a, "56e612b305cb8c5590ce208101eedd75e9a2da17f14c50a49f8294c719ffc133");
		cout << ret << endl;

		ret = BN_hex2bn(&b, "ffffffff");
		cout << ret << endl;
		ret = BN_GF2m_mod(c_mod, a, b);
		cout << ret << endl;
		ret = BN_GF2m_mod_div(c_div, a, b, b, ctx);
		cout << ret << endl;

		cout << BN_bn2hex(c_mod) << "  " << BN_bn2hex(c_div) << endl;
		// char* BN_bn2hex(const BIGNUM * a);

	//	 int BN_GF2m_mod(BIGNUM * r, const BIGNUM * a, const BIGNUM * p);
	/* BN_GF2m_mod_div(BIGNUM * r, const BIGNUM * a, const BIGNUM * b,
		 const BIGNUM * p, BN_CTX * ctx);*/

	}
	return;

	const char* ra = "1";


	int ret;

	char blindPoint[1024] = { 0 };
	EC_POINT* pointa = EC_POINT_new(g_curve_params->group);
	EC_POINT* blind_pointa = EC_POINT_new(g_curve_params->group);

	//EC_POINT_hex2point(g_curve_params->group, point, pointa, ctx);

	//return;

	int i = 0;
	int count = 1000;
	while (true)
	{
		char temp[256] = { 0 };
		sprintf(temp, "%x", i);

		ret = BN_hex2bn(&n, temp);
		ret = EC_POINT_mul(g_curve_params->group, blind_pointa, NULL, g_curve_params->G, n, ctx);
		if (ret == 1) {


			//POINT_CONVERSION_UNCOMPRESSED   POINT_CONVERSION_COMPRESSED  POINT_CONVERSION_HYBRID
			char* result = EC_POINT_point2hex(g_curve_params->group, blind_pointa, POINT_CONVERSION_COMPRESSED, ctx);
			cout << temp << "	|	" << result << endl;

			//if (i%5==0)
			//{
			//	cout << endl;
			//}
			//cout << temp << "	| " << result<<"	|";// << endl;
			OPENSSL_free(result);



		}
		i++;
		if (i >= count)
		{
			break;

		}

	}


	BN_CTX_free(ctx);
	BN_free(n);
	EC_POINT_free(pointa);
	EC_POINT_free(blind_pointa);
}

void testPoint() {
	BN_CTX* ctx = BN_CTX_new();

	char* hex = "04d6597d465408e6e11264c116dd98b539740e802dc756d7eb88741696e20dfe7d3588695d2e7ad23cbf0aa056d42afada63036d66a1d9b97070dd6bc0c87ceb0d";
	EC_POINT* priNumPoint = EC_POINT_new(g_curve_params->group);

	/*
	EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
							 EC_POINT *, BN_CTX *);
							 */
	EC_POINT_hex2point(g_curve_params->group, hex, priNumPoint, ctx);

	char* result = EC_POINT_point2hex(g_curve_params->group, priNumPoint, POINT_CONVERSION_COMPRESSED, ctx);
	cout << hex << "	|" << result << endl;

}
void testPoint2() {
	BN_CTX* ctx = BN_CTX_new();

	char* hex = "04d6597d465408e6e11264c116dd98b539740e802dc756d7eb88741696e20dfe7d3588695d2e7ad23cbf0aa056d42afada63036d66a1d9b97070dd6bc0c87ceb0d";
	EC_POINT* priNumPoint = EC_POINT_new(g_curve_params->group);

	/*
	EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
							 EC_POINT *, BN_CTX *);
							 */
	EC_POINT_hex2point(g_curve_params->group, hex, priNumPoint, ctx);

	char* result = EC_POINT_point2hex(g_curve_params->group, priNumPoint, POINT_CONVERSION_COMPRESSED, ctx);
	cout << hex << "	|" << result << endl;

}
void testReverse() {
	BN_CTX* ctx = BN_CTX_new();
	int ret;
	char* hex = "2";
	BIGNUM* hex_bn = BN_new();
	BIGNUM* hex_bn_reverse = BN_new();
	//BN_div
	ret = BN_hex2bn(&hex_bn, hex);
	/*
	BIGNUM *BN_mod_inverse(BIGNUM *ret,
					   const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
					   */
	BIGNUM* in_ret = BN_mod_inverse(hex_bn_reverse, hex_bn, g_curve_params->order, ctx);
	//char* BN_bn2hex(const BIGNUM * a);
	char* result = BN_bn2hex(hex_bn_reverse);
	cout << result << endl;
	//7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1

}

void testBN() {
	//BN_div
	char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03e";
	//char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03F";
	//char* bStr = "2";
	char* bStr = "ff";
	int ret;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* a_bn = BN_new();
	BIGNUM* b_bn = BN_new();
	BIGNUM* c_bn = BN_new();
	BIGNUM* d_bn = BN_new();
	BIGNUM* temp_bn = BN_new();
	//BN_div
	ret = BN_hex2bn(&a_bn, aStr);
	ret = BN_hex2bn(&temp_bn, bStr);
	ret = BN_hex2bn(&b_bn, bStr);
	/*
	 rem ("dv=a/d, rem=a%d")
	 int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,
				   BN_CTX *ctx);


int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
		   BN_CTX *ctx);

		   */
	int i = 0;
	int count = 256;
	while (true)
	{
		if (BN_cmp(temp_bn, b_bn) == 0)
		{
			temp_bn = a_bn;
		}
		//int BN_div(BIGNUM * dv, BIGNUM * rem, const BIGNUM * a, const BIGNUM * d,
		//	BN_CTX * ctx);

		char* result_a = BN_bn2hex(temp_bn);//被除数

		ret = BN_div(c_bn, d_bn, temp_bn, b_bn, ctx);
		temp_bn = c_bn;


		char* result = BN_bn2hex(c_bn);//商
		char* result_d = BN_bn2hex(d_bn);//余数
		//cout << result_d << endl;
		cout << i << "		|" << result << " | " << result_d << " |" << result_a << endl;

		if (i >= count)
		{
			break;
		}
		i++;
	}


	//ret = BN_div(c_bn, d_bn, a_bn, b_bn,ctx);
	//char* result = BN_bn2hex(c_bn);
	//char* result_d = BN_bn2hex(d_bn);
	//cout << result_d << endl;
	//cout << result << endl;


}
void testBNList() {
	cout << "分解a/b" << endl;
	char a[256] = { 0 };
	char b[256] = { 0 };
	cin >> a;
	cin >> b;
	//BN_div
	char* aStr = (char*)a;
	char* bStr = (char*)b;
	//char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03e";
	//char* bStr = "2";
	int ret;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* a_bn = BN_new();
	BIGNUM* b_bn = BN_new();
	BIGNUM* c_bn = BN_new();
	BIGNUM* d_bn = BN_new();
	BIGNUM* temp_bn = BN_new();
	//BN_div
	ret = BN_hex2bn(&a_bn, aStr);
	ret = BN_hex2bn(&temp_bn, bStr);
	ret = BN_hex2bn(&b_bn, bStr);
	/*
	 rem ("dv=a/d, rem=a%d")
	 int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,
				   BN_CTX *ctx);


int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
		   BN_CTX *ctx);

		   */
	int i = 0;
	int count = 256;
	while (true)
	{
		if (BN_cmp(temp_bn, b_bn) == 0)
		{
			temp_bn = a_bn;
		}
		//int BN_div(BIGNUM * dv, BIGNUM * rem, const BIGNUM * a, const BIGNUM * d,
		//	BN_CTX * ctx);

		char* result_a = BN_bn2hex(temp_bn);//被除数

		ret = BN_div(c_bn, d_bn, temp_bn, b_bn, ctx);
		temp_bn = c_bn;


		char* result = BN_bn2hex(c_bn);//商
		char* result_d = BN_bn2hex(d_bn);//余数
		//cout << result_d << endl;
		cout << i << "		|" << result << " | " << result_d << " |" << result_a << endl;

		if (BN_is_zero(c_bn))
		{

			break;
		}


		if (i >= count)
		{
			break;
		}
		i++;
	}


	//ret = BN_div(c_bn, d_bn, a_bn, b_bn,ctx);
	//char* result = BN_bn2hex(c_bn);
	//char* result_d = BN_bn2hex(d_bn);
	//cout << result_d << endl;
	//cout << result << endl;


}

void testBNAddList() {
	cout << "(add)分解a/b" << endl;
	char a[256] = { 0 };
	char b[256] = { 0 };
	cin >> a;
	cin >> b;
	//BN_div
	char* aStr = (char*)a;
	char* bStr = (char*)b;
	//char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03e";
	//char* bStr = "2";
	int ret;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* a_bn = BN_new();
	BIGNUM* b_bn = BN_new();
	BIGNUM* c_bn = BN_new();
	BIGNUM* d_bn = BN_new();
	BIGNUM* temp_bn = BN_new();

	BIGNUM* bn_one = BN_new();
	ret = BN_hex2bn(&bn_one, "1");

	//BN_div
	ret = BN_hex2bn(&a_bn, aStr);
	ret = BN_hex2bn(&temp_bn, bStr);
	ret = BN_hex2bn(&b_bn, bStr);
	/*
	 rem ("dv=a/d, rem=a%d")
	 int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,
				   BN_CTX *ctx);


int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
		   BN_CTX *ctx);

		   */
	int i = 0;
	int count = 256;
	while (true)
	{
		if (BN_cmp(temp_bn, b_bn) == 0)
		{
			temp_bn = a_bn;
		}
		//int BN_div(BIGNUM * dv, BIGNUM * rem, const BIGNUM * a, const BIGNUM * d,
		//	BN_CTX * ctx);
		ret = BN_add(temp_bn, temp_bn, bn_one);

		char* result_a = BN_bn2hex(temp_bn);//被除数

		ret = BN_div(c_bn, d_bn, temp_bn, b_bn, ctx);
		temp_bn = c_bn;


		char* result = BN_bn2hex(c_bn);//商
		char* result_d = BN_bn2hex(d_bn);//余数
		//cout << result_d << endl;
		cout << i << "		|" << result << " | " << result_d << " |" << result_a << endl;

		if (BN_is_zero(c_bn))
		{

			break;
		}


		if (i >= count)
		{
			break;
		}
		i++;
	}


	//ret = BN_div(c_bn, d_bn, a_bn, b_bn,ctx);
	//char* result = BN_bn2hex(c_bn);
	//char* result_d = BN_bn2hex(d_bn);
	//cout << result_d << endl;
	//cout << result << endl;


}

void testBNAdd() {
	//BN_div
	char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03e";
	//char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03F";
	char* bStr = "2";
	int ret;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* a_bn = BN_new();
	BIGNUM* b_bn = BN_new();
	BIGNUM* c_bn = BN_new();
	BIGNUM* d_bn = BN_new();
	BIGNUM* temp_bn = BN_new();
	BIGNUM* bn_one = BN_new();



	//BN_div
	ret = BN_hex2bn(&a_bn, aStr);
	ret = BN_hex2bn(&temp_bn, bStr);
	ret = BN_hex2bn(&b_bn, bStr);
	ret = BN_hex2bn(&bn_one, "1");
	/*
	 rem ("dv=a/d, rem=a%d")
	 int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,
				   BN_CTX *ctx);


int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
		   BN_CTX *ctx);

		   */
	int i = 0;
	int count = 256;
	while (true)
	{
		if (BN_cmp(temp_bn, b_bn) == 0)
		{
			temp_bn = a_bn;
		}
		//int BN_div(BIGNUM * dv, BIGNUM * rem, const BIGNUM * a, const BIGNUM * d,
		//	BN_CTX * ctx);
		//a +1
		ret = BN_add(temp_bn, temp_bn, bn_one);

		char* result_a = BN_bn2hex(temp_bn);//被除数

		ret = BN_div(c_bn, d_bn, temp_bn, b_bn, ctx);
		temp_bn = c_bn;


		char* result = BN_bn2hex(c_bn);//商
		char* result_d = BN_bn2hex(d_bn);//余数
		//cout << result_d << endl;
		cout << i << "		|" << result << " | " << result_d << "	|" << result_a << endl;

		if (i >= count)
		{
			break;
		}
		i++;
	}


	//ret = BN_div(c_bn, d_bn, a_bn, b_bn,ctx);
	//char* result = BN_bn2hex(c_bn);
	//char* result_d = BN_bn2hex(d_bn);
	//cout << result_d << endl;
	//cout << result << endl;


}
void testBNSub() {
	//BN_div
	char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03e";
	//char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03F";
	char* bStr = "2";
	int ret;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* a_bn = BN_new();
	BIGNUM* b_bn = BN_new();
	BIGNUM* c_bn = BN_new();
	BIGNUM* d_bn = BN_new();
	BIGNUM* temp_bn = BN_new();
	BIGNUM* bn_one = BN_new();



	//BN_div
	ret = BN_hex2bn(&a_bn, aStr);
	ret = BN_hex2bn(&temp_bn, bStr);
	ret = BN_hex2bn(&b_bn, bStr);
	ret = BN_hex2bn(&bn_one, "1");
	/*
	 rem ("dv=a/d, rem=a%d")
	 int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,
				   BN_CTX *ctx);


int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
		   BN_CTX *ctx);

		   */
	int i = 0;
	int count = 256;
	while (true)
	{
		if (BN_cmp(temp_bn, b_bn) == 0)
		{
			temp_bn = a_bn;
		}
		//int BN_div(BIGNUM * dv, BIGNUM * rem, const BIGNUM * a, const BIGNUM * d,
		//	BN_CTX * ctx);
		//a +1
		//ret = BN_add(temp_bn, temp_bn, bn_one);
		ret = BN_sub(temp_bn, temp_bn, bn_one);

		char* result_a = BN_bn2hex(temp_bn);//被除数

		ret = BN_div(c_bn, d_bn, temp_bn, b_bn, ctx);
		temp_bn = c_bn;


		char* result = BN_bn2hex(c_bn);//商
		char* result_d = BN_bn2hex(d_bn);//余数
		//cout << result_d << endl;
		cout << i << " |" << result << " |" << result_d << " |" << result_a << endl;

		if (i >= count)
		{
			break;
		}
		i++;
	}


	//ret = BN_div(c_bn, d_bn, a_bn, b_bn,ctx);
	//char* result = BN_bn2hex(c_bn);
	//char* result_d = BN_bn2hex(d_bn);
	//cout << result_d << endl;
	//cout << result << endl;


}

void testBN1() {
	//BN_div
	char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03e";
	//char* aStr = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03F";
	char* bStr = "2";
	int ret;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* a_bn = BN_new();
	BIGNUM* b_bn = BN_new();
	BIGNUM* c_bn = BN_new();
	BIGNUM* d_bn = BN_new();
	BIGNUM* temp_bn = BN_new();
	BIGNUM* temp_bn_one = BN_new();
	//BN_div
	ret = BN_hex2bn(&a_bn, aStr);
	ret = BN_hex2bn(&temp_bn, bStr);
	ret = BN_hex2bn(&temp_bn_one, "1");
	ret = BN_hex2bn(&b_bn, bStr);
	/*
	 rem ("dv=a/d, rem=a%d")
	 int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,
				   BN_CTX *ctx);


int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
		   BN_CTX *ctx);

		   */

	BIGNUM* temp_bn_sub = BN_new();
	BIGNUM* c_bn_sub = BN_new();
	BIGNUM* d_bn_sub = BN_new();


	int i = 0;
	int count = 256;
	while (true)
	{
		if (BN_cmp(temp_bn, b_bn) == 0)
		{
			//ret = BN_add(a_bn, a_bn, temp_bn_one);
			//cout << ret << endl;
			temp_bn = a_bn;
		}
		//ret = BN_add(temp_bn, temp_bn, temp_bn_one);
		//ret = BN_sub(temp_bn_sub, temp_bn, temp_bn_one);
		ret = BN_add(temp_bn_sub, temp_bn, temp_bn_one);



		//int BN_sub(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);

		//int BN_div(BIGNUM * dv, BIGNUM * rem, const BIGNUM * a, const BIGNUM * d,
		//	BN_CTX * ctx);
		ret = BN_div(c_bn_sub, d_bn_sub, temp_bn_sub, b_bn, ctx);


		ret = BN_div(c_bn, d_bn, temp_bn, b_bn, ctx);
		//int BN_add(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);
		//BN_add() adds aand band places the result in r("r=a+b").r may be the same BIGNUM as a or b.
		//cout << ret << endl;
		temp_bn = c_bn;


		char* result = BN_bn2hex(c_bn);
		char* result_d = BN_bn2hex(d_bn);

		char* result_sub = BN_bn2hex(c_bn_sub);//商
		char* result_d_sub = BN_bn2hex(d_bn_sub);//余数
		//cout << result_d << endl;
		//cout << i << "		|" << result << " | " << result_d << endl;
		cout << "  " << i << "		|" << result_sub << " | " << result_d_sub << endl;

		if (i >= count)
		{
			break;
		}
		i++;
	}


	//ret = BN_div(c_bn, d_bn, a_bn, b_bn,ctx);
	//char* result = BN_bn2hex(c_bn);
	//char* result_d = BN_bn2hex(d_bn);
	//cout << result_d << endl;
	//cout << result << endl;


}
void listQ() {
	//03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1
	int i = 0;
	int ret;
	int count = 256;
	BN_CTX* ctx = BN_CTX_new();
	//点
	char* hex_Q = "03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1";
	EC_POINT* Q = EC_POINT_new(g_curve_params->group);

	EC_POINT_hex2point(g_curve_params->group, hex_Q, Q, ctx);
	//数
	char* hex_two_inverse = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";
	BIGNUM* two_inverse = BN_new();
	ret = BN_hex2bn(&two_inverse, hex_two_inverse);

	/*
	EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
							 EC_POINT *, BN_CTX *);
							 */

	EC_POINT* priP = EC_POINT_new(g_curve_params->group);
	EC_POINT* resultP = EC_POINT_new(g_curve_params->group);
	priP = Q;
	while (true)
	{
		if (i >= count) {
			break;
		}

		// Q* 2^1
		if (i == 0)
		{

			EC_POINT_copy(priP, Q);

		}
		else {

			EC_POINT_copy(priP, resultP);
		}

		ret = EC_POINT_mul(g_curve_params->group, resultP, NULL, priP, two_inverse, ctx);
		char* result = EC_POINT_point2hex(g_curve_params->group, resultP, POINT_CONVERSION_COMPRESSED, ctx);
		char* priResult = EC_POINT_point2hex(g_curve_params->group, priP, POINT_CONVERSION_COMPRESSED, ctx);
		cout << i << "	|" << result << "	|" << priResult << endl;

		i++;
	}

}

/* 返回ch字符在sign数组中的序号 */
int getIndexOfSigns(char ch)
{
	if (ch >= '0' && ch <= '9')
	{
		return ch - '0';
	}
	if (ch >= 'A' && ch <= 'F')
	{
		return ch - 'A' + 10;
	}
	if (ch >= 'a' && ch <= 'f')
	{
		return ch - 'a' + 10;
	}
	return -1;
}

/* 十六进制数转换为十进制数 */
long hexToDec(char* source)
{
	long sum = 0;
	long t = 1;
	int i, len;

	len = strlen(source);
	for (i = len - 1; i >= 0; i--)
	{
		sum += t * getIndexOfSigns(*(source + i));
		t *= 16;
	}

	return sum;
}


void listQ_custom() {
	//03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1
	int i = 1;
	int ret;
	int count = 256;
	cout << "输入count" << endl;
	cin >> count;
	BN_CTX* ctx = BN_CTX_new();
	//点
	char* hex_Q = "03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1";
	EC_POINT* Q = EC_POINT_new(g_curve_params->group);

	EC_POINT_hex2point(g_curve_params->group, hex_Q, Q, ctx);
	//数
	char* hex_two_inverse = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";
	BIGNUM* two_inverse = BN_new();

	/*
	EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
							 EC_POINT *, BN_CTX *);
							 */

	EC_POINT* priP = EC_POINT_new(g_curve_params->group);
	EC_POINT* resultP = EC_POINT_new(g_curve_params->group);
	priP = Q;
	while (true)
	{
		if (i >= count) {
			break;
		}
		char temp[256] = { 0 };
		sprintf(temp, "%x", i);
		ret = BN_hex2bn(&two_inverse, temp);



		ret = EC_POINT_mul(g_curve_params->group, resultP, NULL, g_curve_params->G, two_inverse, ctx);
		//char* result = EC_POINT_point2hex(g_curve_params->group, resultP, POINT_CONVERSION_COMPRESSED, ctx);
		char* result = EC_POINT_point2hex(g_curve_params->group, resultP, POINT_CONVERSION_UNCOMPRESSED, ctx);
		//cout << i << "	|" << result <<"	|"<< temp<<   endl;
		//cout << i << "|" << result <<"	|"<< temp <<" ,";
		/*cout << i << "|" << result  <<" ,";*/
		char x[10] = { 0 };
		char y[10] = { 0 };
		int len = strlen(result);
		strncpy(x, result + 2, (len - 2) / 2);
		strncpy(y, result + 2 + (len - 2) / 2, (len - 2) / 2);
		int x_i = hexToDec(x);
		int y_i = hexToDec(y);
		if (strcmp(result, "00") == 0)
		{
			x_i = 0;
			y_i = 0;
		}
		//cout << i << "|" << result << " ,";
		//cout << "(" << x << "," << y << ")  ,";

		//cout << i << " " << result << ", ";
		cout << i << " (" << x_i << "," << y_i << "), ";
		i++;
	}

}


void listQPrint() {
	//03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1

	cout << "分解Q,输入Q、b的逆元" << endl;
	char a[256] = { 0 };
	char b[256] = { 0 };
	cin >> a;
	cin >> b;


	int i = 0;
	int ret;
	int count = 256;
	BN_CTX* ctx = BN_CTX_new();
	//点
	//char* hex_Q = "03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1";
	//char* hex_two_inverse = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";
	char* hex_Q = (char*)a;
	char* hex_two_inverse = (char*)b;



	EC_POINT* Q = EC_POINT_new(g_curve_params->group);

	EC_POINT_hex2point(g_curve_params->group, hex_Q, Q, ctx);
	//数
	BIGNUM* two_inverse = BN_new();
	ret = BN_hex2bn(&two_inverse, hex_two_inverse);

	/*
	EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
							 EC_POINT *, BN_CTX *);
							 */

	EC_POINT* priP = EC_POINT_new(g_curve_params->group);
	EC_POINT* resultP = EC_POINT_new(g_curve_params->group);
	priP = Q;
	while (true)
	{
		if (i >= count) {
			break;
		}

		// Q* 2^1
		if (i == 0)
		{

			EC_POINT_copy(priP, Q);

		}
		else {

			EC_POINT_copy(priP, resultP);
		}

		ret = EC_POINT_mul(g_curve_params->group, resultP, NULL, priP, two_inverse, ctx);
		char* result = EC_POINT_point2hex(g_curve_params->group, resultP, POINT_CONVERSION_COMPRESSED, ctx);
		char* priResult = EC_POINT_point2hex(g_curve_params->group, priP, POINT_CONVERSION_COMPRESSED, ctx);
		cout << i << "	|" << result << "	|" << priResult << endl;

		i++;
	}

}

void listQAddPrint() {
	//03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1
	int i = 0;
	int ret;
	int count = 256;
	BN_CTX* ctx = BN_CTX_new();
	//点

	cout << "(add)分解Q,输入Q、b的逆元" << endl;
	char a[256] = { 0 };
	char b[256] = { 0 };
	cin >> a;
	cin >> b;


	char* hex_Q = (char*)a;

	char* hex_two_inverse = (char*)b;



	//char* hex_Q = "03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1";
	//char* hex_two_inverse = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";


	//char* hex_Q = "02a12191d0439f0d3c812ec10b96b2d29fd043a5fba4bb37ebd7b4569671844058";
	EC_POINT* Q = EC_POINT_new(g_curve_params->group);

	EC_POINT_hex2point(g_curve_params->group, hex_Q, Q, ctx);
	//数
	BIGNUM* two_inverse = BN_new();
	ret = BN_hex2bn(&two_inverse, hex_two_inverse);
	BIGNUM* oneBn = BN_new();
	ret = BN_hex2bn(&oneBn, "1");



	//EC_POINT_add(g_curve_params->group, Q, Q, g_curve_params->G, ctx);

	/*char* result = EC_POINT_point2hex(g_curve_params->group, Q, POINT_CONVERSION_COMPRESSED, ctx);
	cout << result << endl;
	EC_POINT_add(g_curve_params->group, Q, Q, g_curve_params->G,ctx);
	char* result2 = EC_POINT_point2hex(g_curve_params->group, Q, POINT_CONVERSION_COMPRESSED, ctx);
	cout << result2 << endl;*/


	/*
	EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
							 EC_POINT *, BN_CTX *);
							 */

	EC_POINT* priP = EC_POINT_new(g_curve_params->group);
	EC_POINT* resultP = EC_POINT_new(g_curve_params->group);
	EC_POINT* temp = EC_POINT_new(g_curve_params->group);
	priP = Q;
	while (true)
	{
		if (i >= count) {
			break;
		}

		// Q* 2^1
		if (i == 0)
		{

			EC_POINT_copy(priP, Q);

		}
		else {

			EC_POINT_copy(priP, resultP);
		}
		EC_POINT_copy(temp, priP);

		EC_POINT_add(g_curve_params->group, priP, priP, g_curve_params->G, ctx);

		ret = EC_POINT_mul(g_curve_params->group, resultP, NULL, priP, two_inverse, ctx);
		char* result = EC_POINT_point2hex(g_curve_params->group, resultP, POINT_CONVERSION_COMPRESSED, ctx);
		char* priResult = EC_POINT_point2hex(g_curve_params->group, priP, POINT_CONVERSION_COMPRESSED, ctx);
		char* tempResult = EC_POINT_point2hex(g_curve_params->group, temp, POINT_CONVERSION_COMPRESSED, ctx);
		cout << i << "	|" << result << " |" << priResult << " |" << tempResult << endl;

		i++;
	}

}
void listQAdd() {
	//03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1
	int i = 0;
	int ret;
	int count = 256;
	BN_CTX* ctx = BN_CTX_new();
	//点
	char* hex_Q = "03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1";
	//char* hex_Q = "02a12191d0439f0d3c812ec10b96b2d29fd043a5fba4bb37ebd7b4569671844058";
	EC_POINT* Q = EC_POINT_new(g_curve_params->group);

	EC_POINT_hex2point(g_curve_params->group, hex_Q, Q, ctx);
	//数
	char* hex_two_inverse = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";
	BIGNUM* two_inverse = BN_new();
	ret = BN_hex2bn(&two_inverse, hex_two_inverse);
	BIGNUM* oneBn = BN_new();
	ret = BN_hex2bn(&oneBn, "1");



	//EC_POINT_add(g_curve_params->group, Q, Q, g_curve_params->G, ctx);

	/*char* result = EC_POINT_point2hex(g_curve_params->group, Q, POINT_CONVERSION_COMPRESSED, ctx);
	cout << result << endl;
	EC_POINT_add(g_curve_params->group, Q, Q, g_curve_params->G,ctx);
	char* result2 = EC_POINT_point2hex(g_curve_params->group, Q, POINT_CONVERSION_COMPRESSED, ctx);
	cout << result2 << endl;*/


	/*
	EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
							 EC_POINT *, BN_CTX *);
							 */

	EC_POINT* priP = EC_POINT_new(g_curve_params->group);
	EC_POINT* resultP = EC_POINT_new(g_curve_params->group);
	EC_POINT* temp = EC_POINT_new(g_curve_params->group);
	priP = Q;
	while (true)
	{
		if (i >= count) {
			break;
		}

		// Q* 2^1
		if (i == 0)
		{

			EC_POINT_copy(priP, Q);

		}
		else {

			EC_POINT_copy(priP, resultP);
		}
		EC_POINT_copy(temp, priP);

		EC_POINT_add(g_curve_params->group, priP, priP, g_curve_params->G, ctx);

		ret = EC_POINT_mul(g_curve_params->group, resultP, NULL, priP, two_inverse, ctx);
		char* result = EC_POINT_point2hex(g_curve_params->group, resultP, POINT_CONVERSION_COMPRESSED, ctx);
		char* priResult = EC_POINT_point2hex(g_curve_params->group, priP, POINT_CONVERSION_COMPRESSED, ctx);
		char* tempResult = EC_POINT_point2hex(g_curve_params->group, temp, POINT_CONVERSION_COMPRESSED, ctx);
		cout << i << "	|" << result << "	|" << priResult << "	|" << tempResult << endl;

		i++;
	}

}
void listReminder() {

	//int BN_mod_exp(BIGNUM * r, const BIGNUM * a, const BIGNUM * p,
	//	const BIGNUM * m, BN_CTX * ctx);
	int i = 1, ret, count = 256;
	char* hex_two_inverse = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* bn_two_inverse = BN_new();
	ret = BN_hex2bn(&bn_two_inverse, hex_two_inverse);
	BIGNUM* bn_result = BN_new();
	BIGNUM* bn_p = BN_new();
	BIGNUM* bn_sum = BN_new();

	while (true)
	{
		if (i >= count)
		{
			break;
		}
		char temp[256] = { 0 };
		sprintf(temp, "%x", i);
		//cout << temp << endl;
		ret = BN_hex2bn(&bn_p, temp);

		ret = BN_mod_exp(bn_result, bn_two_inverse, bn_p, g_curve_params->p, ctx);
		//int BN_mod_add(BIGNUM * r, BIGNUM * a, BIGNUM * b, const BIGNUM * m,
			//BN_CTX * ctx);
		ret = BN_mod_add(bn_sum, bn_sum, bn_result, g_curve_params->p, ctx);

		//cout << ret << endl;
		char* result = BN_bn2hex(bn_result);
		char* result_sum = BN_bn2hex(bn_sum);
		cout << hex << i << "	|" << result << "	|" << result_sum << endl;

		i++;

	}
}

void testVarify() {
	//  Q0
	//char* hex_Q = "022412DF506CCE338AE81D64E91473053927B0D49FDB8A65BB18D57708904A3A63";
	//char* hex_QAdd = "03E38660566B6B3C84C1B400F3EEC12E19C1F9572F238B048A1301B664FDF95356";
	//char* hex_Remainder = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";

	  //Q1
	//char* hex_Q = "02F/*07E86CB34E1F4AA80BE8AE8FCCD3243A9941A556E47E63601203BAB535532A8";
	//char* hex_QAdd = "032134AA60A114D4EEC0C99103B504B0730551871D2FF30C8570068567686BFD78";
	//char* hex_Remainder = "2759C7356071A6F179A5FD78744AADF698B0902038B8F7B3032AC0F2ADC4F358";*/


	// Q2
	//char* hex_Q = "03EF0998F5F61C7723A6BAA80E9D5D6ED614F894C2127566422F5F40A668492672";
	//char* hex_QAdd = "025B3A131241F7D9EBB6B6261E152797C781D7BF839D8DA1EF4CA6085D14E56806";
	//char* hex_Remainder = "E043DC0FE28D7F995785D6621D21D0FBD4D4C0DD9D2D3241FD3A531DF5EAB7A9";

	  //Q3
	//char* hex_Q = "034F65791A11372CF65C2A17A754AA9135D7CAEEDD41D664002251FA1675A926CC";
	//char* hex_QAdd = "037CC49DDBD92F4AE763BD692A3618303D163BD666D661529F9CD94B6F2C4D054D";
	//char* hex_Remainder = "6C8E46B9498C0C361DABD1B5393D5EDEA62A9CE12AEC16C22561B9AF9588723D";

	//   Q4
	//char* hex_Q = "03B7D3865AEAA879596C97AB5F4F656421379951BAA850B576A6DDF17B5B0A1C83";
	//char* hex_QAdd = "0331AF2FD35D9DF22227BF3F7CF06E63F7BF8329C036968826BF8833E3BDDBEE2D";
	//char* hex_Remainder = "3362C26953AC80D553EA06DF6205D0BED893C4610FE7BC214A5794F83C5D1763"; 

	//   Q5
	//char* hex_Q = "029B7B2412DA7DD255367DB4811717FDCE7E8BA06290D6BE3D5E1C3866CEDCDC20";
	//char* hex_QAdd = "02222FF6635CCD8FAC3C66DC88CA9DD18EB8906FEDCB60D4B92DC1EE068EC064E2";
	//char* hex_Remainder = "39B9D7EF4023AAF2E262C2750D2B2C77B7267004F4B905C8E7AA696315922841";

	//验证1
	int i = 0;
	int count = 0;

	char* QList[] = { "022412DF506CCE338AE81D64E91473053927B0D49FDB8A65BB18D57708904A3A63",
		"07E86CB34E1F4AA80BE8AE8FCCD3243A9941A556E47E63601203BAB535532A8",
		"03EF0998F5F61C7723A6BAA80E9D5D6ED614F894C2127566422F5F40A668492672",
		"034F65791A11372CF65C2A17A754AA9135D7CAEEDD41D664002251FA1675A926CC",
		"03B7D3865AEAA879596C97AB5F4F656421379951BAA850B576A6DDF17B5B0A1C83",
		"029B7B2412DA7DD255367DB4811717FDCE7E8BA06290D6BE3D5E1C3866CEDCDC20",
		""

	};
	char* remainder_lists[] = { "0",
	"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1",
	"2759C7356071A6F179A5FD78744AADF698B0902038B8F7B3032AC0F2ADC4F358",
	"E043DC0FE28D7F995785D6621D21D0FBD4D4C0DD9D2D3241FD3A531DF5EAB7A9",
	"6C8E46B9498C0C361DABD1B5393D5EDEA62A9CE12AEC16C22561B9AF9588723D",
	"3362C26953AC80D553EA06DF6205D0BED893C4610FE7BC214A5794F83C5D1763"
	};

	while (true)
	{


		//  Q0
		//char* hex_Q = "022412DF506CCE338AE81D64E91473053927B0D49FDB8A65BB18D57708904A3A63";
		//char* hex_QAdd = "0";
		//char* hex_Remainder = "0";
		char* hex_Q = QList[i];
		char* hex_QAdd = "0";
		char* hex_Remainder = remainder_lists[i];
		//Q1
	  //char* hex_Q = "02F/*07E86CB34E1F4AA80BE8AE8FCCD3243A9941A556E47E63601203BAB535532A8";
	  //char* hex_QAdd = "032134AA60A114D4EEC0C99103B504B0730551871D2FF30C8570068567686BFD78";
	  //char* hex_Remainder = "2759C7356071A6F179A5FD78744AADF698B0902038B8F7B3032AC0F2ADC4F358";*/


	  // Q2
	  //char* hex_Q = "03EF0998F5F61C7723A6BAA80E9D5D6ED614F894C2127566422F5F40A668492672";
	  //char* hex_QAdd = "025B3A131241F7D9EBB6B6261E152797C781D7BF839D8DA1EF4CA6085D14E56806";
	  //char* hex_Remainder = "E043DC0FE28D7F995785D6621D21D0FBD4D4C0DD9D2D3241FD3A531DF5EAB7A9";

		//Q3
	  //char* hex_Q = "034F65791A11372CF65C2A17A754AA9135D7CAEEDD41D664002251FA1675A926CC";
	  //char* hex_QAdd = "037CC49DDBD92F4AE763BD692A3618303D163BD666D661529F9CD94B6F2C4D054D";
	  //char* hex_Remainder = "6C8E46B9498C0C361DABD1B5393D5EDEA62A9CE12AEC16C22561B9AF9588723D";

	  //   Q4
	  //char* hex_Q = "03B7D3865AEAA879596C97AB5F4F656421379951BAA850B576A6DDF17B5B0A1C83";
	  //char* hex_QAdd = "0331AF2FD35D9DF22227BF3F7CF06E63F7BF8329C036968826BF8833E3BDDBEE2D";
	  //char* hex_Remainder = "3362C26953AC80D553EA06DF6205D0BED893C4610FE7BC214A5794F83C5D1763"; 

	  //   Q5
	  //char* hex_Q = "029B7B2412DA7DD255367DB4811717FDCE7E8BA06290D6BE3D5E1C3866CEDCDC20";
	  //char* hex_QAdd = "02222FF6635CCD8FAC3C66DC88CA9DD18EB8906FEDCB60D4B92DC1EE068EC064E2";
	  //char* hex_Remainder = "39B9D7EF4023AAF2E262C2750D2B2C77B7267004F4B905C8E7AA696315922841";



	  //验证1 结束



		int ret;
		BN_CTX* ctx = BN_CTX_new();
		BIGNUM* bn_hex_Remainder = BN_new();
		ret = BN_hex2bn(&bn_hex_Remainder, hex_Remainder);

		EC_POINT* ec_hex_Q = EC_POINT_new(g_curve_params->group);
		EC_POINT* ec_hex_QAdd = EC_POINT_new(g_curve_params->group);
		EC_POINT* ec_hex_Remainder = EC_POINT_new(g_curve_params->group);
		EC_POINT* ec_hex_sum = EC_POINT_new(g_curve_params->group);
		EC_POINT* ec_hex_target = EC_POINT_new(g_curve_params->group);

		EC_POINT_hex2point(g_curve_params->group, hex_Q, ec_hex_Q, ctx);
		EC_POINT_hex2point(g_curve_params->group, hex_QAdd, ec_hex_QAdd, ctx);
		ret = EC_POINT_mul(g_curve_params->group, ec_hex_Remainder, NULL, g_curve_params->G, bn_hex_Remainder, ctx);


		ret = EC_POINT_add(g_curve_params->group, ec_hex_sum, ec_hex_Q, ec_hex_QAdd, ctx);

		ret = EC_POINT_invert(g_curve_params->group, ec_hex_Remainder, ctx);

		ret = EC_POINT_add(g_curve_params->group, ec_hex_target, ec_hex_sum, ec_hex_Remainder, ctx);

		char* result_target = EC_POINT_point2hex(g_curve_params->group, ec_hex_target, POINT_CONVERSION_COMPRESSED, ctx);
		char* result_add = EC_POINT_point2hex(g_curve_params->group, ec_hex_sum, POINT_CONVERSION_COMPRESSED, ctx);
		char* result_invert = EC_POINT_point2hex(g_curve_params->group, ec_hex_Remainder, POINT_CONVERSION_COMPRESSED, ctx);

		cout << result_target << " |" << result_add << " |" << result_invert << endl;
		if (i >= count)
		{
			break;

		}
		i++;
	}
}
void testVarifyQ() {

	char* hex_Q = "03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1";
	//char* hex_Remainder = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";
	char* hex_Remainder = "9c9268448a8b3b47555f3c904c33af1a2cb4f3b2f64524cae24ddadb68bce108";//2^1 +  (2^1)^2
	//B8EA14DA821BD8A7DDDFD8E9A8D723053C2430BD64743A8EFA0F922B4825C451  (1/2)^3 

	int ret;	BN_CTX* ctx = BN_CTX_new();



	//char* Q0 = "08A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D81F";
	//char* Q0 = "0451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC0F";  //k1
	char* Q0 = "0228C22D7BFFA9CAAED7C1FB8CEE075DEC068150805EEBC978683949A46C7607";  //k2
	EC_POINT* ec_hex_Remainder = EC_POINT_new(g_curve_params->group);
	BIGNUM* bn_hex_Remainder = BN_new();
	ret = BN_hex2bn(&bn_hex_Remainder, Q0);
	//Q0 = k0 * P
	ret = EC_POINT_mul(g_curve_params->group, ec_hex_Remainder, NULL, g_curve_params->G, bn_hex_Remainder, ctx);
	char* result_invert = EC_POINT_point2hex(g_curve_params->group, ec_hex_Remainder, POINT_CONVERSION_COMPRESSED, ctx);
	cout << result_invert << endl;
	//计算出k1*pk
	//计算出，2^-1*p   
	//相加
	EC_POINT* ec_hex_Remainder2 = EC_POINT_new(g_curve_params->group);
	EC_POINT* ec_hex_sum = EC_POINT_new(g_curve_params->group);
	BIGNUM* bn_hex_Remainder2 = BN_new();
	ret = BN_hex2bn(&bn_hex_Remainder2, hex_Remainder);

	ret = EC_POINT_mul(g_curve_params->group, ec_hex_Remainder2, NULL, g_curve_params->G, bn_hex_Remainder2, ctx);
	char* result_invert2 = EC_POINT_point2hex(g_curve_params->group, ec_hex_Remainder2, POINT_CONVERSION_COMPRESSED, ctx);
	cout << result_invert2 << endl;

	ret = EC_POINT_add(g_curve_params->group, ec_hex_sum, ec_hex_Remainder, ec_hex_Remainder2, ctx);
	char* result_invert3 = EC_POINT_point2hex(g_curve_params->group, ec_hex_sum, POINT_CONVERSION_COMPRESSED, ctx);
	cout << result_invert3 << endl;


	//EC_POINT* ec_hex_Q = EC_POINT_new(g_curve_params->group);
	//EC_POINT* ec_hex_Q_result = EC_POINT_new(g_curve_params->group);
	//BIGNUM* bn_hex_Remainder1 = BN_new();
	//ret = BN_hex2bn(&bn_hex_Remainder1, hex_Remainder);
	////Q0 = Q * 2^-1
	//EC_POINT_hex2point(g_curve_params->group, hex_Q, ec_hex_Q, ctx);

	//ret = EC_POINT_mul(g_curve_params->group, ec_hex_Q_result, NULL, ec_hex_Q, bn_hex_Remainder1, ctx);

	//char* result_invert1 = EC_POINT_point2hex(g_curve_params->group, ec_hex_Q_result, POINT_CONVERSION_COMPRESSED, ctx);
	//cout << result_invert1 << endl;


}
void listTarget() {

	char* k_lists[] = { "08A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D81F",
		"0451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC0F",
		"0228C22D7BFFA9CAAED7C1FB8CEE075DEC068150805EEBC978683949A46C7607",
		"01146116BDFFD4E5576BE0FDC67703AEF60340A8402F75E4BC341CA4D2363B03",
		"8A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D81",
		"451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC0"
	};
	int i = 0;
	int count = 5;
	int ret;
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* bn_k = BN_new();
	BIGNUM* bn_k2 = BN_new();
	EC_POINT* ec_target = EC_POINT_new(g_curve_params->group);
	EC_POINT* ec_target_temp = EC_POINT_new(g_curve_params->group);
	EC_POINT* ec_target_temp2 = EC_POINT_new(g_curve_params->group);

	while (true)
	{
		ret = BN_hex2bn(&bn_k, k_lists[i]);

		ret = BN_mod_add(bn_k2, bn_k, bn_k, g_curve_params->p, ctx);
		ret = EC_POINT_mul(g_curve_params->group, ec_target, NULL, g_curve_params->G, bn_k2, ctx);

		ret = EC_POINT_add(g_curve_params->group, ec_target_temp, ec_target, g_curve_params->G, ctx);

		ret - EC_POINT_copy(ec_target_temp2, g_curve_params->G);

		ret = EC_POINT_invert(g_curve_params->group, ec_target_temp2, ctx);

		ret = EC_POINT_add(g_curve_params->group, ec_target_temp2, ec_target, ec_target_temp2, ctx);


		char* result = EC_POINT_point2hex(g_curve_params->group, ec_target, POINT_CONVERSION_COMPRESSED, ctx);
		char* result_temp = EC_POINT_point2hex(g_curve_params->group, ec_target_temp, POINT_CONVERSION_COMPRESSED, ctx);
		char* result_temp2 = EC_POINT_point2hex(g_curve_params->group, ec_target_temp2, POINT_CONVERSION_COMPRESSED, ctx);
		cout << i << "	|" << result << "	|" << result_temp << "	|" << result_temp2 << endl;

		if (i >= 5) {
			break;
		}
		i++;
	}

	//0 | 08A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D81F | 0
	//	1 | 0451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC0F | 01
	//	2 | 0228C22D7BFFA9CAAED7C1FB8CEE075DEC068150805EEBC978683949A46C7607 | 01
	//	3 | 01146116BDFFD4E5576BE0FDC67703AEF60340A8402F75E4BC341CA4D2363B03 | 01
	//	4 | 8A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D81 | 01
	//	5 | 451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC0 | 01


	//	6 | 228C22D7BFFA9CAAED7C1FB8CEE075DEC068150805EEBC978683949A46C760 | 0
	//	7 | 1146116BDFFD4E5576BE0FDC67703AEF60340A8402F75E4BC341CA4D2363B0 | 0
	//	8 | 08A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D8 | 0
	//	9 | 0451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC | 0
	//	10 | 0228C22D7BFFA9CAAED7C1FB8CEE075DEC068150805EEBC978683949A46C76 | 0
	//	11 | 01146116BDFFD4E5576BE0FDC67703AEF60340A8402F75E4BC341CA4D2363B | 0
}

void listTargetSingle() {

	char* k_lists[] = { "08A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D81F",
		"0451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC0F",
		"0228C22D7BFFA9CAAED7C1FB8CEE075DEC068150805EEBC978683949A46C7607",
		"01146116BDFFD4E5576BE0FDC67703AEF60340A8402F75E4BC341CA4D2363B03",
		"8A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D81",
		"451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC0"
	};
	int i = 0;
	int count = 5;
	int ret;
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* bn_k = BN_new();
	BIGNUM* bn_k2 = BN_new();
	EC_POINT* ec_target = EC_POINT_new(g_curve_params->group);
	EC_POINT* ec_target_temp = EC_POINT_new(g_curve_params->group);
	EC_POINT* ec_target_temp2 = EC_POINT_new(g_curve_params->group);

	while (true)
	{
		ret = BN_hex2bn(&bn_k, k_lists[i]);

		//ret = BN_mod_add(bn_k2, bn_k, bn_k, g_curve_params->p, ctx);
		ret = EC_POINT_mul(g_curve_params->group, ec_target, NULL, g_curve_params->G, bn_k, ctx);

		ret = EC_POINT_add(g_curve_params->group, ec_target_temp, ec_target, g_curve_params->G, ctx);

		ret - EC_POINT_copy(ec_target_temp2, g_curve_params->G);

		ret = EC_POINT_invert(g_curve_params->group, ec_target_temp2, ctx);

		ret = EC_POINT_add(g_curve_params->group, ec_target_temp2, ec_target, ec_target_temp2, ctx);


		char* result = EC_POINT_point2hex(g_curve_params->group, ec_target, POINT_CONVERSION_COMPRESSED, ctx);
		char* result_temp = EC_POINT_point2hex(g_curve_params->group, ec_target_temp, POINT_CONVERSION_COMPRESSED, ctx);
		char* result_temp2 = EC_POINT_point2hex(g_curve_params->group, ec_target_temp2, POINT_CONVERSION_COMPRESSED, ctx);
		cout << i << "	|" << result << "	|" << result_temp << "	|" << result_temp2 << endl;

		if (i >= 5) {
			break;
		}
		i++;
	}

	//0 | 08A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D81F | 0
	//	1 | 0451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC0F | 01
	//	2 | 0228C22D7BFFA9CAAED7C1FB8CEE075DEC068150805EEBC978683949A46C7607 | 01
	//	3 | 01146116BDFFD4E5576BE0FDC67703AEF60340A8402F75E4BC341CA4D2363B03 | 01
	//	4 | 8A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D81 | 01
	//	5 | 451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC0 | 01


	//	6 | 228C22D7BFFA9CAAED7C1FB8CEE075DEC068150805EEBC978683949A46C760 | 0
	//	7 | 1146116BDFFD4E5576BE0FDC67703AEF60340A8402F75E4BC341CA4D2363B0 | 0
	//	8 | 08A308B5EFFEA72ABB5F07EE33B81D77B01A0542017BAF25E1A0E52691B1D8 | 0
	//	9 | 0451845AF7FF53955DAF83F719DC0EBBD80D02A100BDD792F0D0729348D8EC | 0
	//	10 | 0228C22D7BFFA9CAAED7C1FB8CEE075DEC068150805EEBC978683949A46C76 | 0
	//	11 | 01146116BDFFD4E5576BE0FDC67703AEF60340A8402F75E4BC341CA4D2363B | 0
}
void testDouble() {
	char x[100] = { 0 };
	char x_4[100] = { 0 };
	//x3 = x ^ 4 - 56x / 4(x ^ 3 + 7)

	int ret;	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* bn_hex_a = BN_new();
	ret = BN_hex2bn(&bn_hex_a, x);
	BIGNUM* bn_hex_b = BN_new();
	ret = BN_hex2bn(&bn_hex_b, "4");

	BIGNUM* bn_hex_r = BN_new();
	BIGNUM* bn_hex_x4 = BN_new();

	ret = BN_mod_exp(bn_hex_x4, bn_hex_a, bn_hex_b, g_curve_params->p, ctx);
	char* r = BN_bn2hex(bn_hex_x4);
	cout << "x^4:" << r << endl;

}
void testBNArithmetic2() {
	int a1 = 0;
	int p1 = 0;
	char a[256] = { 0 };
	char b[256] = { 0 };
	//char r[256] = {0};
	//cout << "r = a+b" << endl;
	//cout << "r = a-b" << endl;
	//cout << "r = a*b" << endl;
	//cout << "r = a^b" << endl;
	//cout << "r = a/b" << endl;
	//cout << "r = a^(-1) modp" << endl;
	//cout << "a:" << endl;
	//cout << "dec2hex a:" << endl;
	cout << "hex2dec a:" << endl;
	char p[256] = { 0 };
	cin >> a;
	//cin >> a1;
	//cout << "p:" << endl;
	//cin >> p1;
	//cout << "b:" << endl;
	//cin >> b;
	//sprintf(a, "%x", a1);
	//sprintf(p, "%x", p1);

	int ret;	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* bn_hex_a = BN_new();
	BIGNUM* bn_hex_b = BN_new();
	BIGNUM* bn_hex_r = BN_new();
	BIGNUM* bn_hex_mod = BN_new();
	BIGNUM* bn_hex_p = BN_new();

	ret = BN_hex2bn(&bn_hex_a, a);
	//ret = BN_dec2bn(&bn_hex_a, a);
	ret = BN_hex2bn(&bn_hex_b, b);
	ret = BN_hex2bn(&bn_hex_p, p);

	//ret = BN_add(bn_hex_r, bn_hex_a, bn_hex_b);
	//BN_mod_add(bn_hex_r, bn_hex_a, bn_hex_b, g_curve_params->p,ctx);
	//BN_mod_sub(bn_hex_r, bn_hex_a, bn_hex_b, g_curve_params->p,ctx);
	//ret = BN_mod_mul(bn_hex_r, bn_hex_a, bn_hex_b, g_curve_params->p,ctx);

	//ret = BN_mod_exp(bn_hex_r, bn_hex_a, bn_hex_b, g_curve_params->p, ctx);

	//ret = BN_div(bn_hex_r, bn_hex_mod, bn_hex_a, bn_hex_b, ctx);
	//乘法逆元
	//BIGNUM* in_ret = BN_mod_inverse(bn_hex_r, bn_hex_a, g_curve_params->order, ctx);
	//BIGNUM* in_ret = BN_mod_inverse(bn_hex_r, bn_hex_a, g_curve_params->p, ctx);
	//BIGNUM* in_ret = BN_mod_inverse(bn_hex_r, bn_hex_a, bn_hex_p, ctx);

	//int BN_mod_mul(BIGNUM * r, const BIGNUM * a, const BIGNUM * b, const BIGNUM * m,
	//	BN_CTX * ctx);
	/*BN_mod_sub(BIGNUM * r, const BIGNUM * a, const BIGNUM * b, const BIGNUM * m,
		BN_CTX * ctx);*/


		//进制转换

		//char* r =BN_bn2hex(bn_hex_r);
		//char* r =BN_bn2hex(bn_hex_a);
	char* r = BN_bn2dec(bn_hex_a);
	char* mod = BN_bn2hex(bn_hex_mod);

	//char* r = BN_bn2dec(bn_hex_r);
	//char* mod = BN_bn2dec(bn_hex_mod);

	cout << r << endl;
	//cout << r <<"	|"<< mod<<endl;

}

void testBNArithmetic() {
	int a1 = 0;
	int p1 = 0;
	char a[256] = { 0 };
	char b[256] = { 0 };
	//char r[256] = {0};
	//cout << "r = a+b" << endl;
	//cout << "r = a-b" << endl;
	//cout << "r = a*b" << endl;
	//cout << "r = a^b" << endl;
	cout << "r = a^-1/2 mod p" << endl;
	//cout << "r = a/b" << endl;
	//cout << "r = a^(-1)" << endl;
	cout << "a:" << endl;
	char p[256] = { 0 };
	//cin >> a;
	cin >> a1;
	cout << "p:" << endl;
	cin >> p1;
	//cout << "b:" << endl;
	//cin >> b;
	sprintf(a, "%x", a1);
	sprintf(p, "%x", p1);

	int ret;	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* bn_hex_a = BN_new();
	BIGNUM* bn_hex_b = BN_new();
	BIGNUM* bn_hex_r = BN_new();
	BIGNUM* bn_hex_mod = BN_new();
	BIGNUM* bn_hex_p = BN_new();

	ret = BN_hex2bn(&bn_hex_a, a);
	ret = BN_hex2bn(&bn_hex_b, b);
	ret = BN_hex2bn(&bn_hex_p, p);

	//ret = BN_add(bn_hex_r, bn_hex_a, bn_hex_b);
	//BN_mod_add(bn_hex_r, bn_hex_a, bn_hex_b, g_curve_params->p,ctx);
	//BN_mod_sub(bn_hex_r, bn_hex_a, bn_hex_b, g_curve_params->p,ctx);
	//ret = BN_mod_mul(bn_hex_r, bn_hex_a, bn_hex_b, g_curve_params->p,ctx);

	//ret = BN_mod_exp(bn_hex_r, bn_hex_a, bn_hex_b, g_curve_params->p, ctx);

	//ret = BN_div(bn_hex_r, bn_hex_mod, bn_hex_a, bn_hex_b, ctx);
	//乘法逆元
	//BIGNUM* in_ret = BN_mod_inverse(bn_hex_r, bn_hex_a, g_curve_params->order, ctx);
	//BIGNUM* in_ret = BN_mod_inverse(bn_hex_r, bn_hex_a, bn_hex_p, ctx);
	BN_mod_sqrt(bn_hex_r, bn_hex_a, bn_hex_p, ctx);

	//int BN_mod_sqrt(BIGNUM * r, BIGNUM * a, const BIGNUM * m, BN_CTX * ctx);

	//int BN_mod_mul(BIGNUM * r, const BIGNUM * a, const BIGNUM * b, const BIGNUM * m,
	//	BN_CTX * ctx);
	/*BN_mod_sub(BIGNUM * r, const BIGNUM * a, const BIGNUM * b, const BIGNUM * m,
		BN_CTX * ctx);*/


		//char* r = BN_bn2hex(bn_hex_r);
		//char* mod = BN_bn2hex(bn_hex_mod);

	char* r = BN_bn2dec(bn_hex_r);
	char* mod = BN_bn2dec(bn_hex_mod);

	cout << r << endl;
	//cout << r <<"	|"<< mod<<endl;

}

void testECArithmetic() {
	char a[256] = { 0 };
	char b[256] = { 0 };
	//char r[256] = {0};
	//cout << "r = a+b" << endl;
	//cout << "r = a-b" << endl;
	cout << "r = point（a）*b" << endl;
	cin >> a;
	cin >> b;


	int ret;	BN_CTX* ctx = BN_CTX_new();

	/*BIGNUM* bn_hex_a = BN_new();
	BIGNUM* bn_hex_b = BN_new();
	BIGNUM* bn_hex_r = BN_new();*/


	EC_POINT* ec_a = EC_POINT_new(g_curve_params->group);
	EC_POINT* ec_b = EC_POINT_new(g_curve_params->group);
	EC_POINT* ec_r = EC_POINT_new(g_curve_params->group);
	BIGNUM* bn_n = BN_new();
	ret = BN_hex2bn(&bn_n, b);

	EC_POINT_hex2point(g_curve_params->group, a, ec_a, ctx);
	EC_POINT_hex2point(g_curve_params->group, b, ec_b, ctx);

	//Q0 = k0 * P
	ret = EC_POINT_mul(g_curve_params->group, ec_r, NULL, ec_a, bn_n, ctx);
	//求逆

   //ret = EC_POINT_invert(g_curve_params->group, ec_b, ctx);

   //ret = EC_POINT_add(g_curve_params->group, ec_r, ec_a, ec_b, ctx);


	char* result_invert = EC_POINT_point2hex(g_curve_params->group, ec_r, POINT_CONVERSION_COMPRESSED, ctx);
	cout << result_invert << endl;


}
void testBtc() {
	/*
	* Q=03CC8B1586E35545FBC5186A184D0A406F8DD56B73761E9A1C25CB9803489246C1
	* k=1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03e
	* P=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
	* 1/2=7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
	*
	*

	p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
The curve E: y2 = x3 + ax + b over Fp is defined by:

a = 0000000000000000000000000000000000000000000000000000000000000000
b = 0000000000000000000000000000000000000000000000000000000000000007

0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

G = 04
79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

n =   FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
2^-1 =7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
(2^-1)P = 0200000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63
*/
	char* priNum = "1146116bdffd4e5576be0fdc67703aef60340a8402f75e4bc341ca4d2363b03e";
	char* pubKey = "03cc8b1586e35545fbc5186a184d0a406f8dd56b73761e9a1c25cb9803489246c1";
	char* testNum = "2";
	char* n;
	char* p;


	//testPoint();
	//testReverse();


	//void mulityPoint(char* factor, char* point, char** ourRes) {
	char* factor = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1";
	char* gPoint = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	char* outPoint = (char*)malloc(256);
	mulityPoint(factor, gPoint, &outPoint);
	//cout << outPoint << endl;
	//testBN();
	//testBNSub();
	//testBN1();
	//testBNList();
	//testBNAdd();
	//testBNAddList();
	//listQAddPrint();
	//listQ();
	listQ_custom();
	//listQPrint();
	//listQAdd();
	//listReminder();
	//testVarify();
	//testVarifyQ();
	//testECArithmetic();
	//testBNArithmetic();
	//listTargetSingle();
	//listTarget();

	return;
	BN_CTX* ctx = BN_CTX_new();

	int ret;
	BIGNUM* priNum_bn = BN_new();

	ret = BN_hex2bn(&priNum_bn, priNum);
	cout << ret << endl;
	EC_POINT* priNumPoint = EC_POINT_new(g_curve_params->group);

	ret = EC_POINT_mul(g_curve_params->group, priNumPoint, NULL, g_curve_params->G, priNum_bn, ctx);

	if (ret == 1) {


		//POINT_CONVERSION_UNCOMPRESSED   POINT_CONVERSION_COMPRESSED  POINT_CONVERSION_HYBRID
		char* result = EC_POINT_point2hex(g_curve_params->group, priNumPoint, POINT_CONVERSION_COMPRESSED, ctx);
		cout << priNum << "	|" << result << endl;

		//if (i%5==0)

	}
}
void testBtc2() {
	//哈希，转点，x求y2
	//testBtc();
	//testBtc2();
	//free(outMulity);
	cout << "testBtc2 next" << endl;

	char hash[65] = { '0' };
	//this->sm3Hash(data, hash);

	BIGNUM* bignum = BN_new();
	BIGNUM* mod_x = BN_new();
	BIGNUM* y2 = BN_new();
	BIGNUM* y = BN_new();
	BIGNUM* startBN = BN_new();
	BIGNUM* sqrtTmp;//= BN_new();
	BIGNUM* p = g_curve_params->p;
	BN_CTX* ctx = BN_CTX_new();

	int ret = BN_hex2bn(&bignum, hash);
	BN_mod(mod_x, bignum, p, ctx);

	//int i = 0;
	//int index = 1;
	//int max_retry = 100;
	//INT_MAX  ULONG_MAX
	unsigned long i = 0;
	unsigned long index = 1;
	unsigned long max_retry = ULONG_MAX;
	//unsigned long max_retry = 100;

		//cout << "输入数量：" << endl;
		//cin >> max_retry;

	char startX[256] = { 0 };
	//cout << "输入startX:(03|633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852)" << endl;
	//cin >> startX;
	//ret = BN_hex2bn(&startBN, startX);
	ret = BN_dec2bn(&startBN, startX);
	int isbegin = 0;
	char beginX[10] = { 0 };
	while (1) {
		if (i >= max_retry)
		{
			break;
		}
		char temp[256] = { 0 };
		sprintf(temp, "%x", i);

		BN_hex2bn(&bignum, temp);
		//BN_add(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);
		//int BN_add(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);
		ret = BN_add(bignum, bignum, startBN);

		BN_mod(mod_x, bignum, p, ctx);

		ComputeYSquare(mod_x, g_curve_params, &y2);
		bool y_no_zearo = 1;
		if (BN_is_zero(y2) == 1)
		{
			//y2=0
			//cout <<"y2=0,"<< mod_x << endl;
			y_no_zearo = 0;
		}
		int hasSqrt = isSqure(y2, g_curve_params);//0 没有平方根
		if (!hasSqrt && y_no_zearo) {
			// 没有模平方根，再次哈希或者 mod_x + 1 ,重试
		//       printf("  重试第i次 = %d\n",i);

			BIGNUM* addRes = BN_new();
			BIGNUM* add1 = BN_new();
			BN_hex2bn(&add1, "1");
			BN_add(addRes, mod_x, add1);
			BN_copy(mod_x, addRes);

			BN_free(addRes);
			BN_free(add1);
			i++;
			continue;
		}

		sqrtTmp = BN_mod_sqrt(y, y2, g_curve_params->p, ctx);

		if (sqrtTmp == NULL) {

			printf("sqrtTmp null ,y = %s\n", BN_bn2hex(y));
		}

		//    计算出了x，y，计算出点
		char* str_x = BN_bn2dec(mod_x);
		char* str_y = BN_bn2dec(y);

		//int BN_sub(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);
		BIGNUM* y2 = BN_new();
		BN_sub(y2, p, y);
		char* str_y2 = BN_bn2dec(y2);



		/*cout << "("<<str_x <<","<< str_y<<")" << endl;
		cout<< "(" << str_x << "," << str_y2 << ")" << endl;*/



		if (isbegin == 0)
		{
			isbegin = 1;
			strcpy(beginX, str_x);
			cout << "第一次：" << str_x << endl;

		}
		else
		{

			if (strcmp(str_x, beginX) == 0)
			{
				break;
			}

		}

		if (strcmp(str_y, "0") == 0)
		{

			index += 1;
			cout << "(" << str_x << "," << str_y << ")  ";
			//cout << "(" << str_x << "," << str_y << ")  " <<endl;

		}
		else {

			index += 2;
			cout << "(" << str_x << "," << str_y << ")" << " (" << str_x << "," << str_y2 << ")";
			//cout << "(" << str_x << "," << str_y << ")" << " (" << str_x << "," << str_y2 << ")" << endl;

		}
		i++;


	}


	cout << "\nindex:" << index << "  ,p=" << BN_bn2dec(p) << " ,n=" << index << endl;


	// BN_free(sqrtTmp);
	BN_free(y);
	BN_free(y2);
	BN_free(mod_x);
	BN_free(bignum);
	BN_CTX_free(ctx);
}

void RAPSIUtilOpenSSL::data2Point(char* data, char* point) {
	//哈希，转点，x求y2
	//testBtc();
	//testBtc2();
	//testBNArithmetic();
	//free(outMulity);
	bntest();
	

}

void testOpenssl1() {
	/*
char *plain  = "hello";
	int len = strlen(plain);
	char hash[100] = {0};
//    raHashSM3(plain, len, hash);

   */

}

void genRipple(char* pubStr) {

	char step3[100] = { 0 };
	//char* step3 =(char*) malloc(1024);
	raHashSha256(pubStr, strlen(pubStr) / 2, step3);



	char Ripe160_step4[100] = { 0 };
	raHashRipe160(step3, strlen(step3) / 2, Ripe160_step4);

	//16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN   x64
	//003ee4133d991f52fdf6a25c9834e0745ac74248a441544743
	//3ee4133d991f52fdf6a25c9834e0745ac74248a4
	//3EE4133D991F52FDF6A25C9834E0745AC74248A4
	//3EE4, 133D, 991F, 52FD, F6A2, 5C98, 34E0, 745A, C742, 48A4
	char target[] = "3EE4133D991F52FDF6A25C9834E0745AC74248A4";

	int a = 8;

	if (strncmp(Ripe160_step4, target, a) == 0 ||
		strncmp(Ripe160_step4 + 8, target + 8, a) == 0 ||
		strncmp(Ripe160_step4 + 8 * 2, target + 8 * 2, a) == 0 ||
		strncmp(Ripe160_step4 + 8 * 3, target + 8 * 3, a) == 0 ||
		strncmp(Ripe160_step4 + 8 * 4, target + 8 * 4, a) == 0
		)
	{

		cout << "pub:" << pubStr << endl;
		cout << "step3:" << step3 << endl;
		cout << "step4:" << Ripe160_step4 << endl;
	}




}
void genRandom(char* res) {
	char pubStr[256] = { 0 };
	int count = 1;
	int temp1 = rand() % 8;

	count = count + temp1;
	//count = 8;
	//cout << count << endl;
	for (int i = 0; i < count; i++) {
		char temp[10] = { 0 };
		int a = rand();
		//printf("%x\n", a);
		sprintf(temp, "%x", a);
		strcat(pubStr, temp);
		//         sprintf((char*)h[i], "%x",temp);
	}
	strcpy(res, pubStr);
	//strcpy(res, "6B8B4567327B23C6643C98696633487374B0DC5119495CFF2AE8944A625558EC");
	//cout << "" << pubStr << endl;
}
void genAddrRipple() {
	/*
	2.公钥
	3.sha256
	4..ripe160
	5.加版本
	6.sha256
	7.sha256
	8.后四位拼接到第5步之后
	9.base58编码
	*/
	//char* pubStr = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6";
	//char* pubStr = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";

	while (1)
	{

		//输入公钥，产生随机数
		char* pubStr = (char*)malloc(100);
		genRandom(pubStr);


		char* pub02 = (char*)malloc(100);
		char* pub03 = (char*)malloc(100);
		sprintf(pub02, "02%s", pubStr);
		sprintf(pub03, "03%s", pubStr);
		genRipple(pub02);
		genRipple(pub03);
		free(pub02);
		free(pub03);
		free(pubStr);
	}

}

const char* const ALPHABET =
"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const char ALPHABET_MAP[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
	-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
};

int base58decode(const std::string input, int len, unsigned char* result) {

	unsigned char const* str = (unsigned const char*)(input.c_str());
	result[0] = 0;
	int resultlen = 1;
	for (int i = 0; i < len; i++) {
		unsigned int carry = (unsigned int)ALPHABET_MAP[str[i]];
		for (int j = 0; j < resultlen; j++) {
			carry += (unsigned int)(result[j]) * 58;
			result[j] = (unsigned char)(carry & 0xff);
			carry >>= 8;
		}
		while (carry > 0) {
			result[resultlen++] = (unsigned int)(carry & 0xff);
			carry >>= 8;
		}
	}

	for (int i = 0; i < len && str[i] == '1'; i++)
		result[resultlen++] = 0;

	for (int i = resultlen - 1, z = (resultlen >> 1) + (resultlen & 1);
		i >= z; i--) {
		int k = result[i];
		result[i] = result[resultlen - i - 1];
		//printf("%x", k);
		result[resultlen - i - 1] = k;
	}
	return resultlen;
}


int base58encode(const std::string input, int len, unsigned char result[]) {
	unsigned char const* bytes = (unsigned const char*)(input.c_str());
	unsigned char digits[len * 137 / 100];
	int digitslen = 1;
	for (int i = 0; i < len; i++) {
		unsigned int carry = (unsigned int)bytes[i];
		for (int j = 0; j < digitslen; j++) {
			carry += (unsigned int)(digits[j]) << 8;
			digits[j] = (unsigned char)(carry % 58);
			carry /= 58;
		}
		while (carry > 0) {
			digits[digitslen++] = (unsigned char)(carry % 58);
			carry /= 58;
		}
	}
	int resultlen = 0;
	// leading zero bytes
	for (; resultlen < len && bytes[resultlen] == 0;)
		result[resultlen++] = '1';
	// reverse
	for (int i = 0; i < digitslen; i++)
		result[resultlen + i] = ALPHABET[digits[digitslen - 1 - i]];
	result[digitslen + resultlen] = 0;
	return digitslen + resultlen;
}


void runThread(char* priStr) {

	char pubStr[256] = { 0 };
	getPub(priStr, pubStr);
	char addrStr[256] = { 0 };

	genAddr2(pubStr, addrStr);

	char pubX[100] = { 0 };

	char flag[10] = { 0 };

	strncpy(flag, pubStr, 2);
	strncpy(pubX, pubStr + 2, strlen(pubStr) - 2);

	cout << priStr << "|" << addrStr << "|" << flag << "|" << pubX << endl;
	//    printf("%s|%s|%s|%s\n",priStr,addrStr,flag,pubX);
	//    cout.flush();
		//        sprintf(psiVCStrartxRes, " %s \n%s\n %s\n %s  ",priStr,addrStr,indexStr,pubStr);
	//        cout << priStr << "|    " << addrStr << "|    " <<"|"<< pubStr << endl;
	if (strcmp(addrStr, "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN") == 0)
	{
		cout << "find addr:" << addrStr << endl;
		exit(0);
	}
}

void genRandomAddr(char* res) {
	//    srand(time(0)); //time（0）/time（NULL）返回系统当前时间

	char temp[100] = { 0 };
	int count = 2;
	//    unsigned long base = 0x8000000000000000;
	unsigned long base = 0x80000000;
	//    unsigned long range = 0x8000000000000000;
	char random[100] = { 0 };
	unsigned long  a = base + rand() % base;
	sprintf(random, "%lx", a);
	unsigned long  b = rand();
	char random1[100] = { 0 };
	sprintf(random1, "%lx", b);
	strcat(temp, random);
	strcat(temp, random1);
	//       for(int i=0;i<count;i++)
	//       {
	//           char random[100]={0};
	//           int a =rand();
	////       printf("%x\n",a);
	//           sprintf(random, "%x",a);
	//           strcat(temp, random);
	//       }
	//    printf("%s\n",temp  );
	strcpy(res, temp);

}


bool isBig(char* a, char* b, char* r) {
	int ret;    BN_CTX* ctx = BN_CTX_new();

	BIGNUM* bn_a = BN_new();
	BIGNUM* bn_b = BN_new();
	BIGNUM* bn_r = BN_new();
	ret = BN_hex2bn(&bn_a, a);
	ret = BN_hex2bn(&bn_b, b);
	ret = BN_hex2bn(&bn_r, r);
	//    ret = BN_add(bn_r,bn_a,bn_b);
		//char* BN_bn2hex(const BIGNUM * a);

	//    char* res = BN_bn2hex(bn_r);
		//BN_add(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);

	//    strcpy(r, res);

	//     a < b, 0 if a == b and 1 if a > b
	bool status = false;
	if (BN_cmp(bn_a, bn_b) >= 0) {
		status = true;
	}


	BN_CTX_free(ctx);
	BN_free(bn_a);
	BN_free(bn_b);
	BN_free(bn_r);

	//    OPENSSL_free(res);


	return status;

}
void* runSingle(void*) {

	char* random = (char*)malloc(100);
	char* priStr = (char*)malloc(100);
	memset(random, 0, 100);
	memset(priStr, 0, 100);
	//        char priStr[100] = { 0 };
	genRandomAddr(random);
	strcpy(priStr, random);
	//        char* target = "8000000000000000";
	char target[] = "8000000000000000";
	if (isBig(priStr, target, NULL)) {


		runThread(priStr);
	}
	free(random);
	free(priStr);
	pthread_exit(NULL);
}
void runSingle2(void*) {

	char* random = (char*)malloc(100);
	char* priStr = (char*)malloc(100);
	memset(random, 0, 100);
	memset(priStr, 0, 100);
	//        char priStr[100] = { 0 };
	genRandomAddr(random);
	strcpy(priStr, random);
	//        char* target = "8000000000000000";
	char target[] = "8000000000000000";
	if (isBig(priStr, target, NULL)) {


		runThread(priStr);
	}
	free(random);
	free(priStr);
	//    pthread_exit(NULL);
}
void findAddrThread() {

	//    testThread();
	//
	//    return;


		//char* startX = "f99d00000000";

	time_t t;
	/* 初始化随机数发生器 */
	srand((unsigned)time(&t));


	char startX[100] = { 0 };
	//    cout<<psiVCStrartx<<endl;
	cout << "startX f99d000000000000 (f99d 0000 ,0000 0000)" << endl;
	//    cin >> startX;
	//    strcpy(startX, psiVCStrartx);
	cout << "startX:" << startX << endl;
	//LONG_MAX
		//ULONG_MAX
	unsigned long index = 0;
	unsigned long count = ULONG_MAX; //0xffff ffffUL
	//unsigned int count = UINT_MAX;


	while (true)
	{
		if (index > count)
		{
			break;
		}
		pthread_t threads;

		//        rc = pthread_create(&threads[i], NULL,
		//                            PrintHello2,(void*) temp);

		//        runSingle();
		//       int rc = pthread_create(&threads, NULL,
		//                                    runSingle,NULL);
		//        if(rc){
		//            continue;
		//        }
		runSingle2(NULL);


		index++;
	}
}
//
//void cal_x_cube() {
//	//输入p,y
//	//输出 y^2 -7 mod p
//
//}



void cal_x_cube(char* p, char* y, char** res_cube) {
	//输入p,y
	//输出 y^2 -7 mod p
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* big_p = BN_new();
	BIGNUM* big_y = BN_new();
	BIGNUM* big_b = BN_new();
	BIGNUM* big_n = BN_new();
	BIGNUM* big_r = BN_new();
	int ret = BN_hex2bn(&big_b, "7");
	ret = BN_hex2bn(&big_n, "2");

	ret = BN_hex2bn(&big_y, y);
	ret = BN_hex2bn(&big_p, p);


	// ("r=a^p % m")
  //   int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
	//                    const BIGNUM *m, BN_CTX *ctx);

	BN_mod_exp(big_r, big_y, big_n,
		big_p, ctx);

	//        int BN_mod_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
//	BN_CTX* ctx);
	BN_mod_sub(big_r, big_r, big_b, big_p, ctx);

	//char *BN_bn2dec(const BIGNUM *a);
	//char result[100] = { 0 };
	char* result = BN_bn2dec(big_r);
	strcpy(*res_cube, result);

	BN_free(big_p);
	BN_free(big_y);
	BN_free(big_b);
	BN_free(big_n);
	BN_free(big_r);
	BN_CTX_free(ctx);
}


void cal_x(char* p, char* N, char* y, char** res_x) {
	//输入p,N,y
	//输出，y^(N+1) mod p , 立方根
	char* temp;

	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* big_p = BN_new();
	BIGNUM* big_y = BN_new();
	BIGNUM* big_b = BN_new();
	BIGNUM* big_N = BN_new();
	BIGNUM* big_n = BN_new();
	BIGNUM* big_r = BN_new();
	int ret = BN_hex2bn(&big_b, "1");
	ret = BN_hex2bn(&big_N, N);

	//cout << "cal_x  y:" << y << endl;




	ret = BN_hex2bn(&big_n, "2");

	//ret = BN_hex2bn(&big_y, y);
	ret = BN_dec2bn(&big_y, y);
	ret = BN_hex2bn(&big_p, p);



	//int BN_mod_add(BIGNUM * r, BIGNUM * a, BIGNUM * b, const BIGNUM * m,
//	BN_CTX * ctx);

	BN_mod_add(big_n, big_N, big_b, big_p,
		ctx);
	temp = BN_bn2dec(big_n);
	//cout << "n(N+1):" << temp << endl;

	temp = BN_bn2dec(big_y);
	//cout << "big_y:" << temp << endl;

	// ("r=a^p % m")
  //   int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
	//                    const BIGNUM *m, BN_CTX *ctx);


	BN_mod_exp(big_r, big_y, big_n,
		big_p, ctx);


	temp = BN_bn2dec(big_p);
	//cout << "big_p:" << temp << endl;

	temp = BN_bn2dec(big_r);
	//cout << "big_r:" << temp << endl;


	//char *BN_bn2dec(const BIGNUM *a);
	//char result[100] = { 0 };
	char* result = BN_bn2dec(big_r);
	strcpy(*res_x, result);


	BN_free(big_p);
	BN_free(big_y);
	BN_free(big_b);
	BN_free(big_N);
	BN_free(big_n);
	BN_free(big_r);
	BN_CTX_free(ctx);



}
int cal_y_iscube(char* p, char* y) {
	//输入p,y
	//输出 y^(（p-1）/3) mod p是否等于1



	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* big_p = BN_new();
	BIGNUM* big_p_1 = BN_new();
	BIGNUM* big_y = BN_new();
	BIGNUM* big_b = BN_new();
	BIGNUM* big_one = BN_new();

	BIGNUM* big_n = BN_new();
	BIGNUM* big_r = BN_new();
	int ret = BN_hex2bn(&big_b, "3");
	ret = BN_hex2bn(&big_one, "1");

	//ret = BN_hex2bn(&big_y, y);
	ret = BN_dec2bn(&big_y, y);
	ret = BN_hex2bn(&big_p, p);


	//        int BN_mod_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
//	BN_CTX* ctx);
	//p-1
	BN_mod_sub(big_p_1, big_p, big_one, big_p, ctx);

	//rem("dv=a/d, rem=a%d").
	//int BN_div(BIGNUM * dv, BIGNUM * rem, const BIGNUM * a, const BIGNUM * d,
	//	BN_CTX * ctx);

	//p-1/3
	BN_div(big_n, NULL, big_p_1, big_b,
		ctx);


	//int BN_mod_add(BIGNUM * r, BIGNUM * a, BIGNUM * b, const BIGNUM * m,
//	BN_CTX * ctx);



	// ("r=a^p % m")
  //   int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
	//                    const BIGNUM *m, BN_CTX *ctx);


	BN_mod_exp(big_r, big_y, big_n,
		big_p, ctx);

	char* result = BN_bn2dec(big_r);
	//cout << "result:" << result << endl;
	//int BN_is_one(BIGNUM * a);
	int is_cube = BN_is_one(big_r);
	/*if BN_is_one(big_r) == 1{
		is_cube = 1
	}*/


	BN_free(big_p);
	BN_free(big_p_1);
	BN_free(big_y);
	BN_free(big_b);
	BN_free(big_one);
	BN_free(big_n);
	BN_free(big_r);
	BN_CTX_free(ctx);





	return is_cube;
}


void test_next_y_single() {
	//cal_x_cube(char* p, char* y, char** res_cube)
	cout << "test_next_y" << endl;
	//char* p = "2b";
	//char* y = "3";
	//char* N = "4";

	char p_dec[100] = { 0 };
	char y_dec[100] = { 0 };
	char N_dec[100] = { 0 };

	char* p = (char*)malloc(100);
	char* y = (char*)malloc(100);
	char* N = (char*)malloc(100);

	cout << "input p y N" << endl;
	cin >> p_dec >> y_dec >> N_dec;
	cout << "p = " << p_dec << ",y = " << y_dec << ",N = " << N_dec << endl;
	BIGNUM* big_temp = BN_new();

	//BN_dec2bn
	//int BN_dec2bn(BIGNUM * *a, const char* str);
	//	BN_bn2hex
	//	char* BN_bn2hex(const BIGNUM * a);
	char* temp;
	BN_dec2bn(&big_temp, p_dec);
	temp = BN_bn2hex(big_temp);
	strcpy(p, temp);


	BN_dec2bn(&big_temp, y_dec);
	temp = BN_bn2hex(big_temp);
	strcpy(y, temp);


	BN_dec2bn(&big_temp, N_dec);
	temp = BN_bn2hex(big_temp);
	strcpy(N, temp);

	cout << "hex p = " << p << ",y = " << y << ",N = " << N << endl;



	char* res_cube = (char*)malloc(100);
	char* res_x = (char*)malloc(100);
	memset(res_cube, 0, 100);
	cal_x_cube(p, y, &res_cube);
	//cout << "x^3 :" << res_cube << endl;

	cal_x(p, N, res_cube, &res_x);
	//cout << "x:" << res_x << endl;

	//int cal_y_iscube(char* p, char* y)
	int is_cube = cal_y_iscube(p, res_cube);
	//cout << "is_cube:" << is_cube << endl;


	cout << "y=" << y_dec << ",x^3=" << res_cube << ",x=" << res_x << endl;

	free(res_cube);
	free(res_x);
	free(p);
	free(y);
	free(N);

}


void test_next_y_single2(char* p_dec, char* y_dec, char* N_dec) {
	//cal_x_cube(char* p, char* y, char** res_cube)
	//cout << "test_next_y" << endl;
	//char* p = "2b";
	//char* y = "3";
	//char* N = "4";

	/*char p_dec[100] = { 0 };
	char y_dec[100] = { 0 };
	char N_dec[100] = { 0 };*/

	char* p = (char*)malloc(100);
	char* y = (char*)malloc(100);
	char* N = (char*)malloc(100);

	//cout << "input p y N" << endl;
	//cin >> p_dec >> y_dec >> N_dec;
	//cout << "p = " << p_dec << ",y = " << y_dec << ",N = " << N_dec << endl;
	BIGNUM* big_temp = BN_new();

	//BN_dec2bn
	//int BN_dec2bn(BIGNUM * *a, const char* str);
	//	BN_bn2hex
	//	char* BN_bn2hex(const BIGNUM * a);
	char* temp;
	BN_dec2bn(&big_temp, p_dec);
	temp = BN_bn2hex(big_temp);
	strcpy(p, temp);


	BN_dec2bn(&big_temp, y_dec);
	temp = BN_bn2hex(big_temp);
	strcpy(y, temp);


	BN_dec2bn(&big_temp, N_dec);
	temp = BN_bn2hex(big_temp);
	strcpy(N, temp);

	//cout << "hex p = " << p << ",y = " << y << ",N = " << N << endl;



	char* res_cube = (char*)malloc(100);
	char* res_x = (char*)malloc(100);
	memset(res_cube, 0, 100);
	cal_x_cube(p, y, &res_cube);
	//cout << "x^3 :" << res_cube << endl;

	cal_x(p, N, res_cube, &res_x);
	//cout << "x:" << res_x << endl;

	//int cal_y_iscube(char* p, char* y)
	int is_cube = cal_y_iscube(p, res_cube);
	//cout << "is_cube:" << is_cube << endl;

	if (is_cube == 1)
	{
		//cout << "y=" << y_dec << ",x^3=" << res_cube << ",x=" << res_x << endl;
		cout << "(" << y_dec << "," << res_cube << "," << res_x << ")" << endl;

	}

	free(res_cube);
	free(res_x);
	free(p);
	free(y);
	free(N);

}




void test_next_y_list() {


	char p_dec[100] = { 0 };
	char y_dec[100] = { 0 };
	char N_dec[100] = { 0 };

	char* p = (char*)malloc(100);
	char* y = (char*)malloc(100);
	char* N = (char*)malloc(100);

	cout << "input p y N" << endl;
	cin >> p_dec >> y_dec >> N_dec;
	cout << "p = " << p_dec << ",y = " << y_dec << ",N = " << N_dec << endl;

	int count = 100;
	BIGNUM* big_p = BN_new();
	BIGNUM* big_start = BN_new();
	BIGNUM* big_one = (BIGNUM*)BN_value_one();
	BN_dec2bn(&big_p, p_dec);
	//BN_dec2bn(&big_start, "0");
	BN_dec2bn(&big_start, y_dec);
	char* temp;
	BN_CTX* ctx = BN_CTX_new();


	int i = 0;


	while (true)
	{
		/*if (i >= count ){
			break;
		}*/
		if (BN_cmp(big_start, big_p) == 0)
		{
			break;
		}
		temp = BN_bn2dec(big_start);
		//cout << "----------big_start:" << temp << endl;

		test_next_y_single2(p_dec, temp, N_dec);


		//int BN_add(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);
		BN_add(big_start, big_start, big_one);

		//BN_mod_add(big_start, big_start, big_one, big_p, ctx);
		//i++;
	}

}

void test_cube() {
	cout << "test_cube (p , a) " << endl;

	/*
	x1+x2 = p-a
	x1*x2 = a^2

	t= p-a /2
	d^2 = a^2 -t^2
	d = sqrt(d^2)
	x1 = t-d
	x2 = t+d


	*/


	//char* p_str = "43";
	//char* a_str = "32";
	//x1 = 20, x2 = 34
	char p_str[100] = { 0 };
	char a_str[100] = { 0 };
	cin >> p_str >> a_str;
	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_square = BN_new();
	BIGNUM* t = BN_new();
	BIGNUM* t_square = BN_new();
	BIGNUM* inv_2 = BN_new();
	BIGNUM* two = BN_new();
	BIGNUM* d_square = BN_new();
	BIGNUM* d = BN_new();
	BIGNUM* x1 = BN_new();
	BIGNUM* x2 = BN_new();
	BIGNUM* r = BN_new();
	BIGNUM* r2 = BN_new();
	BIGNUM* big_one = (BIGNUM*)BN_value_one();

	//BIGNUM* ret = BN_mod_inverse(rb_1, rb, g_curve_params->order, ctx);

	//BIGNUM* BN_mod_inverse(BIGNUM * r, BIGNUM * a, const BIGNUM * n,
	//	BN_CTX * ctx);

	BN_dec2bn(&p, p_str);
	BN_dec2bn(&a, a_str);
	BN_dec2bn(&two, "2");
	char* temp;
	BN_CTX* ctx = BN_CTX_new();



	/*BN_mod_add
		int BN_sub(BIGNUM * r, const BIGNUM * a, const BIGNUM * b);

		 int BN_mod_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
					   BN_CTX *ctx);

		*/

		//BN_sub( r,  p, a);
	BN_mod_sub(r, p, a, p, ctx);

	BN_mod_inverse(inv_2, two, p, ctx);
	//int BN_mul(BIGNUM * r, BIGNUM * a, BIGNUM * b, BN_CTX * ctx);
	//BN_mul(t, r, inv_2 ,   ctx);
	BN_mod_mul(t, r, inv_2, p, ctx);



	temp = BN_bn2dec(r);
	cout << "---------- p-a:" << temp << endl;


	temp = BN_bn2dec(inv_2);
	cout << "----------inv_2:" << temp << endl;


	temp = BN_bn2dec(t);
	cout << "----------t:" << temp << endl;


	//BN_mod_sqr(BIGNUM * r, BIGNUM * a, const BIGNUM * m, BN_CTX * ctx);

	BN_mod_sqr(a_square, a, p, ctx);
	BN_mod_sqr(t_square, t, p, ctx);
	//BN_mod_sub(d_square, a_square, t_square, p, ctx);
	BN_mod_sub(d_square, t_square, a_square, p, ctx);

	BN_mod_sqrt(d, d_square, p, ctx);

	temp = BN_bn2dec(a_square);
	cout << "----------a_square:" << temp << endl;

	temp = BN_bn2dec(t_square);
	cout << "----------t_square:" << temp << endl;

	temp = BN_bn2dec(d_square);
	cout << "----------d_square:" << temp << endl;
	temp = BN_bn2dec(d);
	cout << "----------d:" << temp << endl;

	BN_mod_sub(x1, t, d, p, ctx);
	BN_mod_add(x2, t, d, p, ctx);

	//temp = BN_bn2dec(x1);
	//cout << "----------x1:" << temp << endl;

	//temp = BN_bn2dec(x2);
	//cout << "----------x2:" << temp << endl;

	char* temp_x1 = BN_bn2dec(x1);
	char* temp_x2 = BN_bn2dec(x2);

	cout << "(" << a_str << "," << temp_x1 << "," << temp_x2 << ")" << endl;


}
void testSquare() {

	char* temp;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_square = BN_new();
	BIGNUM* k = BN_new();

	char* p_str = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
	char* a_str = "54004231326449675249656825592424781987043706074411609924286248221719456227510";
	//char* k_str = "57896044618658097711785492504343953926634992332820282019728792003956564819968";
	//char* k_str = "33554432";
	//char* k_str = "115792089237316195423570985008687907852837564279074904382605163141518161494336";
	//n-1 /2 = 57896044618658097711785492504343953926634992332820282019728792003956564819968
	//char* k_str = "57896044618658097711785492504343953926634992332820282019728792003956564819968";
	char* k_str = "57896044618658097711785492504343953926418782139537452191302581570759080747168";
	             //57896044618658097711785492504343953926418782139537452191302581570759080747168
	//char p_str[100] = { 0 };
	//char a_str[100] = { 0 };
	//char k_str[100] = { 0 };

	//cout << "a^1/2 mod p" << endl;
	//cin >> a_str >> p_str;
	BN_dec2bn(&p, p_str);
	BN_dec2bn(&a, a_str);
	BN_dec2bn(&k, k_str);

	//int BN_mod_sqrt(BIGNUM * r, BIGNUM * a, const BIGNUM * m, BN_CTX * ctx);

	//int ret= BN_mod_sqrt(a_square, a, p, ctx);
	int ret = 0;

	BN_mod_sqrt(a_square, a, p, ctx);
	temp = BN_bn2dec(a_square);
	//cout << a_str << endl;
	cout <<"ret:"<<ret<<", "<< temp << endl;


	//int BN_mod_exp(BIGNUM * r, BIGNUM * a, const BIGNUM * p,
	//	const BIGNUM * m, BN_CTX * ctx);
	//int BN_mod_mul(BIGNUM * r, BIGNUM * a, BIGNUM * b, const BIGNUM * m,
	//	BN_CTX * ctx);

	//ret = BN_mod_exp(a_square, a, k,
	//	p, ctx);

	ret = BN_mod_mul(a_square, a, k,
		p, ctx);


	temp = BN_bn2dec(a_square);
	//cout << a_str << endl;
	cout << "ret:" << ret << ", " << "exp:" << temp << endl;
}
void testBN2() {
	cout << "testBN" << endl;
	int ret = 0;

	char* temp;
	BN_CTX* ctx = BN_CTX_new();

	char p_str[100] = { 0 };
	char a_str[100] = { 0 };
	char k_str[100] = { 0 };
	cout << "p,a,k" << endl;
	cin >> p_str >> a_str >> k_str;

	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* r = BN_new();
	BIGNUM* k = BN_new();


	BN_dec2bn(&p, p_str);
	BN_dec2bn(&a, a_str);
	BN_dec2bn(&k, k_str);


	//ret = BN_mod_exp(r, a, k,
	//	p, ctx);

	ret = BN_mod_mul(r, a, k,
		p, ctx);

	 
	temp = BN_bn2dec(r);
	cout << temp << endl;

}

void getPubBase_dec(char* priStr, char* baseG, char* pubStr) {

	int ret;	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* bn_n = BN_new();
	//ret = BN_hex2bn(&bn_n, priStr);
	ret = BN_dec2bn(&bn_n, priStr);
	EC_POINT* ec_r = EC_POINT_new(g_curve_params->group);

	//EC_POINT* EC_POINT_hex2point(const EC_GROUP * group, const char* hex,
	//	EC_POINT * p, BN_CTX * ctx);

	EC_POINT* ec_base = EC_POINT_new(g_curve_params->group);
	EC_POINT_hex2point(g_curve_params->group, baseG, ec_base, ctx);



	//Q0 = k0 * P
	ret = EC_POINT_mul(g_curve_params->group, ec_r, NULL, ec_base, bn_n, ctx);
	//ret = EC_POINT_mul(g_curve_params->group, ec_r, NULL, g_curve_params->G, bn_n, ctx);


	//int EC_POINT_add(const EC_GROUP * group, EC_POINT * r, const EC_POINT * a,
	//	const EC_POINT * b, BN_CTX * ctx);

	char* result_invert = EC_POINT_point2hex(g_curve_params->group, ec_r, POINT_CONVERSION_COMPRESSED, ctx);
	//cout << result_invert << endl;
	strcpy(pubStr, result_invert);


	BN_CTX_free(ctx);
	BN_free(bn_n);
	EC_POINT_free(ec_r);
	EC_POINT_free(ec_base);
	OPENSSL_free(result_invert);




}

void pointAdd(char* point_a, char* point_b, char* pubStr) {

	int ret;	BN_CTX* ctx = BN_CTX_new();
	 
	EC_POINT* r = EC_POINT_new(g_curve_params->group);
	 
	EC_POINT* a = EC_POINT_new(g_curve_params->group);
	EC_POINT_hex2point(g_curve_params->group, point_a, a, ctx);


	EC_POINT* b = EC_POINT_new(g_curve_params->group);
	EC_POINT_hex2point(g_curve_params->group, point_b, b, ctx);

	 
	
	ret=EC_POINT_add(g_curve_params->group,  r,   a,
			 b,  ctx);

	//int EC_POINT_add(const EC_GROUP * group, EC_POINT * r, const EC_POINT * a,
	//	const EC_POINT * b, BN_CTX * ctx);

	char* result_invert = EC_POINT_point2hex(g_curve_params->group, r, POINT_CONVERSION_COMPRESSED, ctx);
	//cout << result_invert << endl;
	strcpy(pubStr, result_invert);


	BN_CTX_free(ctx);
	 
	EC_POINT_free(r);
	EC_POINT_free(a);
	EC_POINT_free(b);
	OPENSSL_free(result_invert);




}

void testEC2() {
	cout << "testEC2" << endl;

	//char* baseG = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	//char* k = "2";

	char baseG[100] = { 0 };
	char k[100] = { 0 };

	cout << "baseG,k" <<endl;
	cin >> baseG >> k;

	char* priStr = k;

	char pubStr[100] = { 0 };

	getPubBase_dec(priStr, baseG, pubStr);
	cout << pubStr << endl;

}

void testEC3() {
	cout << "testEC3" << endl;

	//char* baseG = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	//char* k = "2";

	char a[100] = { 0 };
	char b[100] = { 0 };

	cout << "a,b" << endl;
	cin >> a >> b;
	char pubStr[100] = { 0 };

	pointAdd(a, b, pubStr);

	//pointAdd(char* point_a, char* point_b, char* pubStr);
	cout << pubStr << endl;

}
void test_bsgs_babyTable_computek_exp(){
	cout<<"test_bsgs_babyTable_computek_exp	\n";
	char* temp;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_result = BN_new();
	BIGNUM* k = BN_new();
	//a**k mod p = a_result

	char a_str[100] = { 0 };
	char k_str[100] = { 0 };
	char p_str[100] = { 0 };
	// cin >> a_str ;
	
	cin >> a_str >>k_str >> p_str;
	BN_hex2bn(&p, p_str);
	// BN_dec2bn(&a, a_str);
	BN_hex2bn(&a, a_str);
	BN_hex2bn(&k, k_str);

	// int BN_mod_exp(BIGNUM * r, BIGNUM * a, const BIGNUM * p,
	// //	const BIGNUM * m, BN_CTX * ctx);
	BN_mod_exp(a_result,a,k,p,ctx );
	char* temp1 = BN_bn2hex(a_result);
	cout<<temp1<<endl;
}
void test_bsgs_babyTable_computek_mul(){
	//r=a*b mod p; 输入：a,b,p；输出r

cout<<"test_bsgs_babyTable_computek_mul	\n";
	char* temp;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_result = BN_new();
	BIGNUM* k = BN_new();
	//a**k mod p = a_result

	char a_str[100] = { 0 };
	char k_str[100] = { 0 };
	char p_str[100] = { 0 };
	// cin >> a_str ;
	
	cin >> a_str >>k_str >> p_str;
	BN_hex2bn(&p, p_str);
	// BN_dec2bn(&a, a_str);
	BN_hex2bn(&a, a_str);
	BN_hex2bn(&k, k_str);

	// int BN_mod_exp(BIGNUM * r, BIGNUM * a, const BIGNUM * p,
	// //	const BIGNUM * m, BN_CTX * ctx);
	BN_mod_exp(a_result,a,k,p,ctx );



        // int BN_mod_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
        //                BN_CTX *ctx);


    BN_mod_mul(a_result,  a, k, p,ctx);



	char* temp1 = BN_bn2hex(a_result);
	cout<<temp1<<endl;
}
void test_bsgs_babytable_computek_64(){

	cout<<"test_bsgs_babyTable_computek_64 	\n";
	char* temp;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_square = BN_new();
	BIGNUM* k = BN_new();

	char* p_str = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
	// char* a_str = "1";
	// char* a_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
	char* k_str = "2";
	             //57896044618658097711785492504343953926418782139537452191302581570759080747168
	//char p_str[100] = { 0 };
	char a_str[100] = { 0 };
	//char k_str[100] = { 0 };
	cin >> a_str ;
	//cout << "a^1/2 mod p" << endl;
	//cin >> a_str >> p_str;
	BN_dec2bn(&p, p_str);
	// BN_dec2bn(&a, a_str);
	BN_hex2bn(&a, a_str);
	BN_dec2bn(&k, k_str);

	//int BN_mod_sqrt(BIGNUM * r, BIGNUM * a, const BIGNUM * m, BN_CTX * ctx);

	//int ret= BN_mod_sqrt(a_square, a, p, ctx);

	 // BIGNUM *BN_copy(BIGNUM *to, const BIGNUM *from);

	BIGNUM* privious_result = BN_new();
	privious_result = BN_copy(privious_result, a);
	for (int i = 0; i < 6; ++i)
	{
		

		// BN_CTX* ctx = BN_CTX_new();
		/* code */
		BIGNUM* bn_result_1 = BN_new();
		BIGNUM* bn_result_2 = BN_new();
		BN_mod_sqrt(bn_result_1, privious_result, p, ctx);
		// BN_mod_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
        //                BN_CTX *ctx);

		BN_mod_sub(bn_result_2,p,bn_result_1,p,ctx);
		char* temp1 = BN_bn2hex(bn_result_1);
		char* temp2 = BN_bn2hex(bn_result_2);
		char* temp_prious = BN_bn2hex(privious_result);

		cout<<"temp_prious " << temp_prious<<endl;
		cout<<temp1<<" " << temp2<<endl;
		BN_copy(privious_result, bn_result_1);
	}

	// int ret = 0;

	// BN_mod_sqrt(a_square, a, p, ctx);
	// temp = BN_bn2dec(a_square);
	// //cout << a_str << endl;
	// cout <<"ret:"<<ret<<", "<< temp << endl;


	// //int BN_mod_exp(BIGNUM * r, BIGNUM * a, const BIGNUM * p,
	// //	const BIGNUM * m, BN_CTX * ctx);
	// //int BN_mod_mul(BIGNUM * r, BIGNUM * a, BIGNUM * b, const BIGNUM * m,
	// //	BN_CTX * ctx);

	// ret = BN_mod_exp(a_square, a, k,
	// 	p, ctx);

	// // ret = BN_mod_mul(a_square, a, k,
	// // 	p, ctx);


	// temp = BN_bn2dec(a_square);
	// //cout << a_str << endl;
	// cout << "ret:" << ret << ", " << "exp:" << temp << endl;


}
void test_bsgs_babytable_computek_sqrt_k(){
	cout<<"test_bsgs_babytable_computek_sqrt_k"<<endl;


	/*
	x**k = 1 mod p;求出一个x

	1.输入一个(x1,a1), x**k = a mod p; 求出另一个x2
	2.求出x1的逆元，x1_inv*x1 = 1 mod p
	3.x = x2* x1_inv, 就是要求的x

	k次剩余求法
	x**k = a mod p ;输入a,k,p;输出一个x

	1.判断a是否有k次剩余； a**(p-1/k) = 1,则a有解
	2.p-1 = k^t * s, t=1 必须为1，否则算法失效
		p-1=k*s
	3.求s，s = p-1/k
	4.求alpha，k*alpha = 1 mod s; alpha=k_inv mod s;  s不一定为素数
	5.求x；x = a** alpha 


	*/


	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* p = BN_new();
	BIGNUM* p_1 = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_result = BN_new();
	BIGNUM* k = BN_new();
	// BIGNUM* bn_one= BN_value_one();
	const BIGNUM* bn_one= BN_value_one();

	// char a_str[100] = "5";
	// char k_str[100] = "5";
	// char p_str[100] = "1f";
	
	cout<<"x**k = a mod p ;输入a,k,p;输出一个x; hex16进制"<<endl;

	char a_str[100] = { 0 };
	char k_str[100] = { 0 };
	char p_str[100] = { 0 };
		cin >> a_str >>k_str >> p_str;


	
	BN_hex2bn(&p, p_str);
	// BN_dec2bn(&a, a_str);
	BN_hex2bn(&a, a_str);
	BN_hex2bn(&k, k_str);

	cout<<"p ="<<BN_bn2hex(p)<<", a = "<< BN_bn2hex(a)<<" ,k= "<<BN_bn2hex(k)<<endl;


	BN_mod_sub(p_1, p, bn_one, p,ctx);
	BIGNUM* s = BN_new();
	BIGNUM* rem = BN_new();

	BN_div(s, rem, p_1, k,ctx);
	char* temp = BN_bn2hex(s);

	cout<<"s= "<< temp <<endl;
	cout<<"p-1= "<<BN_bn2hex(p_1)<<endl;

	BIGNUM* bn_result= BN_new();

//判断a是否有k次剩余； a**(p-1/k) = 1,则a有解
	BN_mod_exp(bn_result, a, s,p, ctx);


	if (BN_cmp(bn_result, bn_one) == 0)
	{
		/* code */
		cout<<"有k次剩余"<<endl;

	BIGNUM* alpha  = BN_new();
	//k*alpha = 1 mod s

	BN_mod_inverse(alpha, k, s,ctx);
	//x = a** alpha mod p
	BIGNUM* bn_result_x= BN_new();
	BN_mod_exp(bn_result_x, a, alpha,p, ctx);

	char* temp1_s = BN_bn2hex(s);
	char* temp1_alpha = BN_bn2hex(alpha);
	char* temp1_x = BN_bn2hex(bn_result_x);

	cout<<"s , alpha ,x "<<endl;
	cout<<"hex: "<<temp1_s<<" "<<temp1_alpha<<" "<<temp1_x<<endl;

	char* temp1_x_dec = BN_bn2dec(bn_result_x);

	cout<<"dec "<<temp1_x_dec<<endl;

	}else{
		cout<<"没有k次剩余"<<endl;
	}

/*

 b from a modulo m and places the nonnegative result in r
 r=a-b
int BN_mod_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
                      BN_CTX *ctx);

rem ("dv=a/d, rem=a%d")
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d,
                   BN_CTX *ctx);
("r=a^p % m")
        int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx);

r ("(a*r)%n==1")
        BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n,
                               BN_CTX *ctx);

 const BIGNUM *BN_value_one(void);

 int BN_is_one(const BIGNUM *a);

returns -1 if a < b, 0 if a == b and 1 if a > b
 int BN_cmp(BIGNUM *a, BIGNUM *b);


*/




}
void test_bsgs_babytable_computek(){
	cout<<"test_bsgs_babytable_computek\n ";

	char* temp;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_result = BN_new();
	BIGNUM* k = BN_new();
	//a**k mod p = a_result

	// char a_str[100] = { 0 };
	// char k_str[100] = { 0 };
	// char p_str[100] = { 0 };
	// 	cin >> a_str >>k_str >> p_str;

	// char a_str[100] = "2c115617b6e750be039cc6291bf66bdce169b9dc344f7c663a54fb7b8347bd7";
	// char k_str[100] = "95";
	// char a_str[100] = "60cd44806c8d40e50073c4857482c70d95bda6a8be7bcae110e0c715c1a3aa4d";
	// char k_str[100] = "277";


	// char a_str[100] = "73aa7c979bb15317727fe8c587825ba6c3422c67cca28c01ac50b2ca1b7ce93b";
	// char k_str[100] = "17d6cfb8ee30c51";



	// char a_str[100] = "779dd6e5189c2695ec5ae789d9bc9fede2b7fd80d66019a65e4a568dbec5a805";
	// char k_str[100] = "978c6f353c3889a79";



	// char a_str[100] = "68450b6d617318cf99cb3172e1682b7ee924dfafad77120055ee9a91fee78e1";
	// char k_str[100] = "10dbff26eab8198050172ee03275";
	// char p_str[100] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	
	
	// char a_str[100] = "9c1f62cbf6ac82b5d18dc2dc940caa0dc368de9aa3b5b21da7675dbecd92bcb2";
	// char k_str[100] = "7";
	// char p_str[100] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	

	
	// char a_str[100] = "7b44303eea567cf3a648949352e4aea882ea466c773eb5035d757e112b01421f";
	// char k_str[100] = "13441";
	// char p_str[100] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	
	char a_str[100] = "c40a0b032253fbc402f27bd211987cdfdaa08f775c37ce842a3a5e26d67922da";
	char k_str[100] = "1db8260e5e3b460a46a0088fccf6a3a5936d75d89a776d4c0da4f338aafb";
	char p_str[100] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
	


	BN_hex2bn(&p, p_str);
	// BN_dec2bn(&a, a_str);
	BN_hex2bn(&a, a_str);
	BN_hex2bn(&k, k_str);

	// int BN_mod_exp(BIGNUM * r, BIGNUM * a, const BIGNUM * p,
	// //	const BIGNUM * m, BN_CTX * ctx);
	// BN_mod_exp(a_result,a,k,p,ctx );
	// char* temp1 = BN_bn2hex(a_result);
	// cout<<temp1<<endl;


	unsigned long index = 1;
	// unsigned long count = ULONG_MAX; //0xffff ffffUL
	unsigned long count = 130; //0xffff ffffUL
	//unsigned int count = UINT_MAX;
	while (true)
	{
		if (index > count)
		{
			break;
		}

		char indexStr[100] = { 0 };
		//sprintf(indexStr, "%lx | %lx",index,count);
		sprintf(indexStr, "%lx", index);
		BN_hex2bn(&k, indexStr);

		BN_mod_exp(a_result,a,k,p,ctx );
		char* temp1 = BN_bn2hex(a_result);
		char* temp1_a = BN_bn2hex(a);
		char* temp1_k = BN_bn2hex(k);
		cout<<temp1_a<< " "<<temp1_k << " "<< temp1<<endl;
		index++;

	}










}
void test_bsgs_babyTable(){
	cout<<"	test_bsgs_babyTable"<<endl;
	//输入a, max_count
	//输出 i ,a**i,pub

//char* startX = "f99d00000000";
	// char startX[100] = { 0 };
	// //cout << "startX f99d000000000000 (f99d 0000 ,0000 0000)" << endl;
	// //cout << "startX 0000000000000000 (  f99cbdfb599ed010  ,0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 );startX" << endl;
	// cout << "startX:" << endl;
	// cin >> startX;
	// cout << "baseG:" << endl;
	// char baseG[100] = { 0 };
	// cin >> baseG;


	char* temp;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_result = BN_new();
	BIGNUM* k = BN_new();


	char* p_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	// char* a_str = "2c115617b6e750be039cc6291bf66bdce169b9dc344f7c663a54fb7b8347bd7";
	
	char a_str[100] = { 0 };
	int max_count=0;
	cin >>a_str>>max_count;

	BN_hex2bn(&p, p_str);
	BN_hex2bn(&a, a_str);
	


	char startX[100] = "1";

	char baseG[100] = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";


	//LONG_MAX
		//ULONG_MAX
	unsigned long index = 1;
	// unsigned long count = ULONG_MAX; //0xffff ffffUL
	unsigned long count = max_count; //0xffff ffffUL
	//unsigned int count = UINT_MAX;
	while (true)
	{
		if (index > count)
		{
			break;
		}

		char indexStr[100] = { 0 };
		//sprintf(indexStr, "%lx | %lx",index,count);
		sprintf(indexStr, "%lx", index);

		BN_hex2bn(&k, indexStr);

// ("r=a^p % m")
//         int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
//                        const BIGNUM *m, BN_CTX *ctx);

		BN_mod_exp(a_result, a, k,p, ctx);


		//cout << indexStr << endl;

		//cout << index << "," << count << endl;
		char* priStr = BN_bn2hex(a_result); 
 
		char pubStr[256] = { 0 };
		getPubBase(priStr, baseG, pubStr);
		

		char flag[10] = { 0 };
		char pubX[100] = { 0 };

		strncpy(flag, pubStr, 2);
		strncpy(pubX, pubStr + 2, strlen(pubStr) - 2);

	
		// cout << priStr << "|" << addrStr << "|" << flag << "|" << pubX << endl;
		// cout << priStr << "|" <<flag<<"|"<<pubX << endl;
		// cout <<indexStr<<" "<< priStr << " " <<pubStr << endl;
		cout <<indexStr<<" "<< priStr << " " <<flag<< " "<< pubX << endl;

		index++;
	}





}
void test_bsgs_giantTable_sub(){
	cout<<"	test_bsgs_giantTable"<<endl;
// Q - i*m*P = b*P

// input: Q, m ,a 
// output: i,i*m, b*P

	char* temp;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_result = BN_new();
	BIGNUM* k = BN_new();


	char* p_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	// char* a_str = "2c115617b6e750be039cc6291bf66bdce169b9dc344f7c663a54fb7b8347bd7";
	// char* Q_str = "031889151027BB7A22F4ACDAC18A09A4BFCD94A673936248DD14F8145D90DA2BC2";
	
	char a_str[100] = { 0 };
	char Q_str[100] = { 0 };
	int max_count=2;
	cin >>a_str>>max_count>>Q_str;
	int m_interval=max_count;


	BN_hex2bn(&p, p_str);
	BN_hex2bn(&a, a_str);
	


	char startX[100] = "1";

	char baseG[100] = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";


	//LONG_MAX
		//ULONG_MAX
	unsigned long index = 1;
	// unsigned long count = ULONG_MAX; //0xffff ffffUL
	unsigned long count = max_count; //0xffff ffffUL
	unsigned long temp_m  = 1; //0xffff ffffUL
	//unsigned int count = UINT_MAX;
	while (true)
	{
		if (index > count)
		{
			break;
		}

		temp_m = m_interval*index;

		char indexStr[100] = { 0 };
		//sprintf(indexStr, "%lx | %lx",index,count);
		sprintf(indexStr, "%lx", temp_m);

		BN_hex2bn(&k, indexStr);

// ("r=a^p % m")
//         int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
//                        const BIGNUM *m, BN_CTX *ctx);

		BN_mod_exp(a_result, a, k,p, ctx);


		//cout << indexStr << endl;

		//cout << index << "," << count << endl;
		char* priStr = BN_bn2hex(a_result); 
 
		char pubStr[256] = { 0 };
		char m_i_pubStr[256] = { 0 };
		getPubBase(priStr, baseG, m_i_pubStr);

		// Q - m_i_pubStr

		// getPubBaseQ_mp(char* Q_str,char*mp_str,char*pubStr);
		getPubBaseQ_mp( Q_str,m_i_pubStr, pubStr);

		char flag[10] = { 0 };
		char pubX[100] = { 0 };

		strncpy(flag, pubStr, 2);
		strncpy(pubX, pubStr + 2, strlen(pubStr) - 2);

	
		// cout << priStr << "|" << addrStr << "|" << flag << "|" << pubX << endl;
		// cout << priStr << "|" <<flag<<"|"<<pubX << endl;
		// cout <<indexStr<<" "<< priStr << " " <<pubStr << endl;
		cout <<indexStr<<" "<< priStr << " " <<flag<< " "<< pubX << endl;

		index++;
	}



}

void test_bsgs_giantTable(){
	cout<<"	test_bsgs_giantTable"<<endl;

	// Q* (a_1)^im = b*P

// input: Q, m ,a 
// output: i,i*m, b*P

	char* temp;
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* a_1 = BN_new();
	BIGNUM* a_result = BN_new();
	BIGNUM* k = BN_new();


	char* p_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
	// char* a_str = "2c115617b6e750be039cc6291bf66bdce169b9dc344f7c663a54fb7b8347bd7";
	// char* Q_str = "031889151027BB7A22F4ACDAC18A09A4BFCD94A673936248DD14F8145D90DA2BC2";
	
	char a_str[100] = { 0 };
	char Q_str[100] = { 0 };
	int max_count=2;
	cin >>a_str>>max_count>>Q_str;
	int m_interval=max_count;


	BN_hex2bn(&p, p_str);
	BN_hex2bn(&a, a_str);
	
	BN_mod_inverse(a_1,  a,p,ctx);


	char startX[100] = "1";

	char baseG[100] = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";


	//LONG_MAX
		//ULONG_MAX
	unsigned long index = 1;
	// unsigned long count = ULONG_MAX; //0xffff ffffUL
	unsigned long count = max_count; //0xffff ffffUL
	unsigned long temp_m  = 1; //0xffff ffffUL
	//unsigned int count = UINT_MAX;
	while (true)
	{
		if (index > count)
		{
			break;
		}

		temp_m = m_interval*index;

		char indexStr[100] = { 0 };
		char indexStr2[100] = { 0 };
		//sprintf(indexStr, "%lx | %lx",index,count);
		sprintf(indexStr, "%lx", temp_m);
		sprintf(indexStr2, "%lx", index);

		BN_hex2bn(&k, indexStr);

		BN_mod_exp(a_result, a_1, k,p, ctx);


		char* priStr = BN_bn2hex(a_result); 
 
		char pubStr[256] = { 0 };
		// char m_i_pubStr[256] = { 0 };

		// Q*(a_1)**(i*m)
		getPubBase(priStr, Q_str, pubStr);


		char flag[10] = { 0 };
		char pubX[100] = { 0 };

		strncpy(flag, pubStr, 2);
		strncpy(pubX, pubStr + 2, strlen(pubStr) - 2);

	
		// cout << priStr << "|" << addrStr << "|" << flag << "|" << pubX << endl;
		// cout << priStr << "|" <<flag<<"|"<<pubX << endl;
		// cout <<indexStr<<" "<< priStr << " " <<pubStr << endl;
		cout <<indexStr2<<" "<<indexStr<<" "<< priStr << " " <<flag<< " "<< pubX << endl;

		index++;
	}



}
static RAPSIUtil * m_util;

void test_bsgs_lookup(){
	cout<<"test_bsgs_lookup"<<endl;
	/*
	输入两个文件，giant, babay
	
8*8 =64


	giant拿出一个数据，跟babay对比
		前8位是否相等，是；接下来位是否相等；
		
		第一位是否相等；
			相等；1.有可能相等；2.不相等
			不相等：一定不相等，寻找下一个；


	*/

  if (m_util == NULL)
    {
        m_util = new RAPSIUtilOpenSSL();
    }

 	cout<<"输入file1 len1； file2 len2 \n";
    char file1[256]={0};
    char file2[256]={0};
    int  file1_len = 0;
    int  file2_len = 0;
  cin>>file1>>file1_len>>file2>>file2_len;
  cout<<file1<<" len "<< file1_len<<endl;
  cout<<file2<<" len "<< file2_len<<endl;

char** clients = (char**)malloc(sizeof(char*) * (file1_len+1));
char** servers = (char**)malloc(sizeof(char*) * (file2_len+1));
 	int inter_count = file1_len;
 	int client_count = file1_len;
 	int server_count = file2_len;

    if (file2_len > file1_len)
    {
        inter_count = file2_len;
    }
    char** intersect = (char**)malloc(sizeof(char*) * inter_count);

   for (int i = 0; i < inter_count; i++) {
        intersect[i] = (char*)malloc(1024);
    }

  //2、创建流对象
  ifstream ifs ,ifs2;
 
  //3、打开文件并且判断是否打开成功
  ifs.open(file1,ios::in) ;
  if (!ifs.is_open()) {
    cout << "file1 文件打开失败" << endl;
    return;
  }

  ifs2.open(file2,ios::in) ;
  if (!ifs2.is_open()) {
    cout << " file2 文件打开失败" << endl;
    return;
  }



 //第二种
  char buf[1024] = { 0 };
  int i = 0;
  while (ifs.getline(buf,sizeof(buf))) {
    // cout << buf << endl;

	char* tmp = (char*)malloc(strlen(buf) + 1);
	strcpy(tmp,buf);
    clients[i] = tmp;
    i++;
  }

  // void *memset(void *s, int c, size_t n);

  memset(buf,0,1024);
  i=0;
while (ifs2.getline(buf,sizeof(buf))) {
    // cout << buf << endl;

	char* tmp = (char*)malloc(strlen(buf) + 1);
	strcpy(tmp,buf);
    servers[i] = tmp;
    i++;
  }


  	int inter_count_before=inter_count;
    m_util->raGetIntersect(clients, client_count, servers, server_count, (char**)intersect, &inter_count);

cout << "inter_count: " << inter_count << endl;
	if (inter_count>0 )
	{
		cout<<"有交集"<<endl;
		for (int i = 0; i < inter_count; i++) {
		        // intersect[i] = (char*)malloc(1024);
		        char* result=intersect[i];
		        cout<<i<<" "<<result<<endl;
		    }

	}
 




	for (int i = 0; i < client_count ; i++)
	{
	    free(clients[i]);
	}

	 for (int i = 0; i < server_count ; i++)
	    {
	        free(servers[i]);
	    }
	 for (int i = 0; i < inter_count_before ; i++)
	    {
	        free(intersect[i]);
	    }


  //5、关闭文件
  ifs.close();
  ifs2.close();



}

/*
 * 将字符转换为数值
 * */
int c2i(char ch)
{
    // 如果是数字，则用数字的ASCII码减去48, 如果ch = '2' ,则 '2' - 48 = 2
    if (isdigit(ch))
        return ch - 48;

    // 如果是字母，但不是A~F,a~f则返回
    if (ch < 'A' || (ch > 'F' && ch < 'a') || ch > 'z')
        return -1;

    // 如果是大写字母，则用数字的ASCII码减去55, 如果ch = 'A' ,则 'A' - 55 = 10
    // 如果是小写字母，则用数字的ASCII码减去87, 如果ch = 'a' ,则 'a' - 87 = 10
    if (isalpha(ch))
        return isupper(ch) ? ch - 55 : ch - 87;

    return -1;
}

/*
 * 功能：将十六进制字符串转换为整型(int)数值
 * */
int hex2dec(char* hex)
{
    int len;
    int num = 0;
    int temp;
    int bits;
    int i;

    // 此例中 hex = "1de" 长度为3, hex是main函数传递的
    len = strlen(hex);

    for (i = 0, temp = 0; i < len; i++, temp = 0)
    {
        // 第一次：i=0, *(hex + i) = *(hex + 0) = '1', 即temp = 1
        // 第二次：i=1, *(hex + i) = *(hex + 1) = 'd', 即temp = 13
        // 第三次：i=2, *(hex + i) = *(hex + 2) = 'd', 即temp = 14
        temp = c2i(*(hex + i));
        // 总共3位，一个16进制位用 4 bit保存
        // 第一次：'1'为最高位，所以temp左移 (len - i -1) * 4 = 2 * 4 = 8 位
        // 第二次：'d'为次高位，所以temp左移 (len - i -1) * 4 = 1 * 4 = 4 位
        // 第三次：'e'为最低位，所以temp左移 (len - i -1) * 4 = 0 * 4 = 0 位
        bits = (len - i - 1) * 4;
        temp = temp << bits;

        // 此处也可以用 num += temp;进行累加
        num = num | temp;
    }

    // 返回结果
    return num;
}
void test_bsgs_split(){

	cout<<"test_bsgs_split"<<endl;
    // const char* file = "c.txt";
    char file[100]={0 };
    
    int slpit_count=1;

    cin>>file>>slpit_count;

    int slpit_count_array=slpit_count*16;
    if (slpit_count == 1)
    {	
    	slpit_count_array=16;
    }else if (slpit_count == 2)
    {
    	slpit_count_array=256;
    }else{
    	cout<<"	文件过多"<<endl;
    	return ;
    }

    cout<<file<<" "<<slpit_count << " " <<slpit_count_array <<endl;



 

    int count = slpit_count_array;
    FILE** outfilesArray = (FILE**)malloc(count * sizeof(FILE*));
    for (int i = 0; i < count; i++)
    {
        char fileStr[256] = { 0 };
        sprintf(fileStr, "./data/%x.txt", i);
        FILE* p = fopen(fileStr, "a");
        if (p == NULL)
        {
            cout << "写入失败" << endl;

            return ;
        }
        outfilesArray[i] = p;

        //fprintf(p, "%x\n", i);
    }



    FILE* p = fopen(file, "r");
    if (p == NULL)
    {
        cout << "文件打开失败" << endl;
    }
    
    /*fputs("1111111\n", p);*/
    //fwrite(file, strlen(file),1,p);
    int copy_len=slpit_count;
    while (!feof(p))
    {

        char buffer[1024] = { 0 };
        // cout << sizeof(buffer);
        //break;
        fgets(buffer, sizeof(buffer), p);
        if (strcmp(buffer,"") == 0)
        {
        	/* code */
        	cout<<"文件结束"<<endl;
        	continue;
        }

        // cout << buffer << endl;
               // char *strcpy(char *dest, const char *src);
        char temp[10]={0};
        // strcpy(temp,buffer	);
               // char *strncpy(char *dest, const char *src, size_t n);

       strncpy(temp, buffer, copy_len);
       int temp_int=hex2dec(temp );

       cout<<"第一个字符： "<<temp<< " , " << temp_int<<endl;

       FILE * temp_p= outfilesArray[temp_int] ;
		fprintf(temp_p, "%s", buffer);
    }

    for (int i = 0; i < count; i++)
    {

        FILE* p = outfilesArray[i];
        fclose(p);
    }



    fclose(p);

}
void test_bsgs(){
	cout<<" test_bsgs"<<endl;
	// test_bsgs_babyTable();
	// test_bsgs_giantTable();


	// test_bsgs_babyTable_computek_64();
	// test_bsgs_babyTable_computek_exp();

	// test_bsgs_babytable_computek();
	// test_bsgs_babytable_computek_sqrt_k();

	// test_bsgs_babyTable_computek_mul();

	// test_bsgs_lookup();
	// test_bsgs_split();
	//findAddr3();
	findAddr4();


}
void test_next_y() {
	
	//test_next_y_list();
	//test_cube();
	//testBN2();
	// testEC3();
	test_bsgs();

}
