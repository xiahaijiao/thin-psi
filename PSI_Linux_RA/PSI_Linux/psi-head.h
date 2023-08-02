 

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
	
	
	
	---------
	
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
	
	
	

// ("r=a^p % m")
        int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx);

//computes the inverse of a modulo n places the result in r ("(a*r)%n==1")
 BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n,
                               BN_CTX *ctx);


 
        char *strcpy(char *dest, const char *src);
       char *strncpy(char *dest, const char *src, size_t n);
