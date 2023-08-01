//
//  RAPSIUtil.hpp
//  RASoftAlg
//
//  Created by john on 2020/6/11.
//  Copyright © 2020 China rongan. All rights reserved.
//

#ifndef RAPSIUtil_hpp
#define RAPSIUtil_hpp

#include <stdio.h>
#define RAPonintCompressType 4
#define dFile "/opt/PSI_Linux_RA/log.txt"

//#define RAPSIDEBUG
void ralog(const char* path, const char* format, ...);

typedef enum ECCType{
    ECC_PolarSSL =1,
    ECC_OpenSSL ,
    ECC_USBKey 
    
}ECCType;

typedef struct ra_entry
{
    char * first;
    char * second;
} RAEntry;


class RAPSIUtil
{
public:
    //转点
    
    /// 原文转点
    /// @param data 待转点原文
    /// @param point 转化后的点
    virtual void data2Point( char* data,char*point);
    
    /// 对一个点盲化
    /// @param point 待盲化点
    /// @param ra 盲化因子
    /// @param blindPoint 已盲化点
    virtual void pointBlindRA(char*point,char*ra,char*blindPoint);
//    求逆
    
    /// 求逆
    /// @param ra 盲化因子
    /// @param ra_1 盲化因子的逆
    virtual void getInverseRA(char*ra,char*ra_1);
    
    /// 哈希
    /// @param data  入参
    /// @param hash 出参
    virtual void sm3Hash(char*data,char*hash);
     
    
    /// 构建映射数组
    /// @param firsts 第一个集合
    /// @param seconds 第二个集合
    /// @param maps 映射数组
    /// @param count 映射数组长度
    void raCreateMaps(char**firsts,char**seconds,RAEntry* maps,int count);
    
    /// 映射查找，根据key找到value，或者根据value找key , 1 success 0 fail
    /// @param datas 映射数组
    /// @param count 映射数组长度
    /// @param key 每条映射的索引
    /// @param value 每条映射的值
    int  raGetValueWithKey(RAEntry *datas,int count,const char*key,char*value);


    
    /// 集合求交集
    /// @param client_sets 第一个集合
    /// @param client_count 第一个集合长度
    /// @param server_sets 第二个集合
    /// @param server_count 第二个集合长度
    /// @param intersect 交集
    /// @param inter_count 交集长度
    void raGetIntersect(char**client_sets,int client_count, char**server_sets,int server_count,char**intersect, int *inter_count);
 
    
};




/// 字符串转二进制  ，  字符串两个字节，二进制1个字节
/// @param str  输入
/// @param UnChar 输出
void convertStrToUnChar(char* str, unsigned char* UnChar);

/// unsigned char 转 char
/// @param str 出参（二进制1个字节  32       (一个字节{0x41}) ， 子符串两个字节 64           ( 两个{4,1})）
/// @param UnChar in
/// @param ucLen in 二进制长度
void convertUnCharToStr(char* str, unsigned char* UnChar, int ucLen);


#endif /* RAPSIUtil_hpp */
