#include <iostream>
#include <fstream>
#include <vector>
#include <math.h>
#include <string.h>
#include "randomnumbersandpermutation.h"
#include <stdio.h>
#include <stdlib.h>
using namespace std;
char * getrandnumbers(int bytenumbers){
     
        //int bytenumbers = 10;
        char* randnumbers = (char*)malloc(bytenumbers+1);
        memset(randnumbers, 0, bytenumbers + 1);

        static int aaa = bytenumbers;
        char buff[1024] = { 0 };


        int i = 1;
        while (i < 125)
        {
            i++;
            int a;
            srand((unsigned)time(NULL) + aaa);
            a = rand();//4¸ö×Ö½Ú£¬  3e2c6f9d
            //printf("random %x\n", a);
            aaa++;
            //printf("i:%d,buff:%s\n", i, buff);
            sprintf((char*)buff, "%s%x", (char*)buff, a);
        }
        //    strcpy(randnumbers, (char*)buff, bytenumbers);
        memcpy(randnumbers, buff, bytenumbers);

        //printf("buff:%s\nrandom:%s\n", (char*)buff, randnumbers);
    





    return randnumbers;
}

vector<string>  randompermutation(vector<string> in){
    vector<string> n=in;

    unsigned int thesize=in.size();

    unsigned int bytenumbers=thesize/8;
    if(bytenumbers*8<thesize){
        bytenumbers+=1;
    }

    std::ifstream readfile;
    readfile.open("/dev/urandom",std::ifstream::binary);
    for(int i=0;i<thesize;i++){
        char *randnumbers=new char [bytenumbers];
        if(readfile.good()){
            readfile.read(randnumbers,bytenumbers);
        }
        unsigned int rdnum=0;
        for(int j=0;j<bytenumbers;j++){
            unsigned int a=pow(8,j);
            unsigned int b=randnumbers[j];
            rdnum+=a*b;
        }
        rdnum=rdnum%thesize;
    cout<<rdnum<<"   ";
        string sp=n[i];
        n[i]=n[rdnum];
        n[rdnum]=sp;

    }
    cout<<endl;
    readfile.close();

    return n;
}
//
//int main()
//{
//    vector<string> a={"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16"};
//
//    for(int i=0;i<a.size();i++){
//        cout<<a[i]<<"    ";
//    }
//    cout << endl;
//
//    vector<string> b=randompermutation(a);
//
//    for(int i=0;i<b.size();i++){
//        cout<<b[i]<<"    ";
//    }
//    cout << endl;
//
//    return 0;
//}
