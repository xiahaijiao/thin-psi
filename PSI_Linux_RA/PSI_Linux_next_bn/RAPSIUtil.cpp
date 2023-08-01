//
//  RAPSIUtil.cpp
//  RASoftAlg
//
//  Created by john on 2020/6/11.
//  Copyright © 2020 China rongan. All rights reserved.
//

#include "RAPSIUtil.hpp"
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#include <string.h>
#include <string>

#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

using namespace std;
//#define    DebugRA

 
void ralog(const char* path, const char* format, ...) {
     FILE* pFile = fopen(path, "a");

va_list arg;
    int done;

    va_start(arg, format);
    //done = vfprintf (stdout, format, arg);

    time_t time_log = time(NULL);
    struct tm* tm_log = localtime(&time_log);
    fprintf(pFile, "%04d-%02d-%02d %02d:%02d:%02d ", tm_log->tm_year + 1900, tm_log->tm_mon + 1, tm_log->tm_mday, tm_log->tm_hour, tm_log->tm_min, tm_log->tm_sec);

    done = vfprintf(pFile, format, arg);
    va_end(arg);
    fflush(pFile);
fclose(pFile);
   // return done;
}

/// unsigned char 转 char
/// @param str 出参（二进制1个字节  32       (一个字节{0x41}) ， 子符串两个字节 64           ( 两个{4,1})）
/// @param UnChar in
/// @param ucLen in 二进制长度
void convertUnCharToStr(char* str, unsigned char* UnChar, int ucLen)
{
    int i = 0;
    for(i = 0; i < ucLen; i++)
    {
        //格式化输str,每unsigned char 转换字符占两位置%x写输%X写输
        sprintf(str + i * 2, "%02X", UnChar[i]);
    }
}

/// 字符串转二进制  ，  字符串两个字节，二进制1个字节
/// @param str  输入
/// @param UnChar 输出
void convertStrToUnChar(char* str, unsigned char* UnChar)
{
    int i = strlen(str), j = 0, counter = 0;
    char c[2];
    unsigned int bytes[2];
  
    for (j = 0; j < i; j += 2)
    {
        if(0 == j % 2)
        {
            c[0] = str[j];
            c[1] = str[j + 1];
            sscanf(c, "%02x" , &bytes[0]);
            UnChar[counter] = bytes[0];
            counter++;
        }
    }
    return;
}


class map_value_finder {
    string m_str;
    
public:
    map_value_finder(string &string){
        this->m_str = string;
    }
    map_value_finder(string string){
           this->m_str = string;
       }
  bool  operator()(map<string, string>::value_type &pair){
      if (pair.second == m_str) {
          return true;
      }
      return false;
    }
};


void RAPSIUtil::data2Point(char *data, char *point){
    
}
void RAPSIUtil::getInverseRA(char *ra, char *ra_1){
    
}
void RAPSIUtil::pointBlindRA(char *point, char *ra, char *blindPoint){
    
}
void RAPSIUtil::sm3Hash(char *data, char *hash){
    
}
vector<string> v_intersect(vector<string>v1, vector<string>v2){
    vector<string>v ;
    sort(v1.begin(), v1.end());
    sort(v2.begin(), v2.end());
    
    set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(), back_inserter(v));
    return v;
}
void printVector(vector<string> v){
    for (vector<string>::iterator it = v.begin(); it != v.end(); it++) {
        cout<< (*it)<<endl;
    }
}
void testVector(){
   /*
    vector<string> v1,v2,v;
    v1.push_back("zabc");
    v1.push_back("abc");
    v1.push_back("aab");
    v1.push_back("abb");
    v1.push_back("acc");
    
    v2.push_back("abc");
    v2.push_back("aab1");
    v2.push_back("abb1");
    v2.push_back("acc");
    
    v = v_intersect(v1, v2);
    printVector(v);

    return;
    
    
    
    
    map<string, string >m ;
    
    m.insert(make_pair("abc", "China"));
    m.insert(make_pair("123", "USA"));
    m.insert(make_pair("xyz", "Japan"));
    
    char* key = "China1";
    map<string, string>::iterator pos = m.find(key);
    if (pos == m.end()) {
        pos = find_if(m.begin(), m.end(), map_value_finder(key));
        if (pos != m.end()) {
            //找到了
            cout<<(*pos).first << "  " << (*pos).second<<endl;

        }else{
            printf("fail");

        }
    }else{
        cout<<(*pos).first << "  " << (*pos).second<<endl;
    }
*/
}
void RAPSIUtil::raCreateMaps(char **firsts, char **seconds, RAEntry *maps, int count){
    for (int i = 0; i < count; i++) {
        RAEntry *map = &maps[i];
        strcpy(map->first, firsts[i]);
        strcpy(map->second, seconds[i]);
        
//        map->first = firsts[i];
//        map->second = seconds[i];
    }
    
//    testVector();
    
}

int RAPSIUtil::raGetValueWithKey(RAEntry *datas, int count, const char *key, char *value){
     map<string, string >m ;
        
        for (int i = 0; i< count; i++) {
//            RAEntry *data = datas[i];
            RAEntry data = datas[i];
            m.insert(make_pair(data.first, data.second));
            
        }
        
         
    //
        int result = 0;
        int isvalue = 0;
            map<string, string>::iterator pos = m.find(key);
        if (pos == m.end()) {
            //
            pos = find_if(m.begin(), m.end(), map_value_finder(key));
        }else{
            isvalue = 1;
        }
             
            if (pos != m.end()) {
                //查找到了，并且是按value查找的，结果应该是返回first
                string tmp2 = (*pos).first ;
                if (isvalue == 1) {
                    //返回second
                    tmp2 = (*pos).second;
                }
               const char *tmp =(const char*)tmp2.data();
                stpcpy(value, tmp);
                cout<<"success "<<(*pos).first<< ", "<<(*pos).second<<endl;
                result = 1;

            }else{
                result= 0;
                cout<<"fail "<<endl;
            }
        
        return result;
}
void RAPSIUtil::raGetIntersect(char **client_sets, int client_count, char **server_sets, int server_count, char **intersect, int *inter_count){
     vector<string>v1,v2,v;
     printf("\n\n");
        for (int i = 0; i < client_count; i++) {
            char* client = client_sets[i];
            //printf("i:%d,client:%s  ;", i, client);
            v1.push_back(client);
        }
        //printf("\n\n");
        for (int i = 0; i < server_count; i++) {
            char *server = server_sets[i];
            v2.push_back(server);
        }
        //printf("\n\n");
        v = v_intersect(v1, v2);
        int i= 0;
        for (vector<string>::iterator it = v.begin(); it != v.end(); it++) {
            int len =(int ) (*it).length();
    //        cout<<*it<<endl;
//            char *it_str =(char*) malloc(len+1);

//ralog(dFile,"jni raGetIntersec %s\n",(*it).data());
            char *it_str = intersect[i];
            strcpy(it_str, (*it).data());
#ifdef DebugRA

ralog(dFile, "jni raGetIntersec it_str %s\n", it_str);

#endif // DebugRA
            
//printf("i:%d, it_str:%s  ;", i, it_str);
            
            intersect[i] = it_str;
            i++;
        }
        *inter_count = i;
        
}
