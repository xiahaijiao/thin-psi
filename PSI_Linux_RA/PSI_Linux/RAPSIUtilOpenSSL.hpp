//
//  RAPSIUtilOpenSSL.hpp
//  RASoftAlg
//
//  Created by john on 2020/6/11.
//  Copyright © 2020 China rongan. All rights reserved.
//

#ifndef RAPSIUtilOpenSSL_hpp
#define RAPSIUtilOpenSSL_hpp

#include <stdio.h>
#include "RAPSIUtil.hpp"
void testOpenssl1();

class RAPSIUtilOpenSSL:public RAPSIUtil {
    
public:
    void data2Point(char *data, char *point) override;
    void pointBlindRA(char *point, char *ra, char *blindPoint) override;
    void getInverseRA(char *ra, char *ra_1) override;
    void sm3Hash(char *data, char *hash) override;


    RAPSIUtilOpenSSL(){
     
         setEcc();
    }

private:
        void setEcc();
};



#endif /* RAPSIUtilOpenSSL_hpp */
