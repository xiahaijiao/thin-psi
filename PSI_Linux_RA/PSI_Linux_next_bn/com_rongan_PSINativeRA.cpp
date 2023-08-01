#include <stdio.h>
#include "com_rongan_PSINativeRA.h" 
#include "RAPSIUtil.hpp"
#include "RAPSIUtilOpenSSL.hpp"
 
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <iostream>

using namespace std;

static RAPSIUtil * m_util;

#define dFile "/opt/PSI_Linux_RA/log.txt"
//#define    DebugRA

#include <assert.h>

#include <sys/stat.h>

#include <sys/types.h>

#include <fcntl.h>

#include <unistd.h>

/* Return a random integer between MIN and MAX, inclusive. Obtain

randomness from /dev/random. */

int random_number(int min, int max)

{

    /* Store a file descriptor opened to /dev/random in a static

    variable. That way, we dont need to open the file every time

    this function is called. */

    static int dev_random_fd = -1;

    char* next_random_byte;

    int bytes_to_read;

    unsigned random_value;

    /* Make sure MAX is greater than MIN. */

    assert(max > min);

    /* If this is the first time this function is called, open a file

    descriptor to /dev/random. */

    if (dev_random_fd == -1) {

        dev_random_fd = open("/dev/random", O_RDONLY);

        assert(dev_random_fd != -1);

    }

    /* Read enough random bytes to fill an integer variable. */

    next_random_byte = (char*)&random_value;

    bytes_to_read = sizeof(random_value);

    /* Loop until weve read enough bytes. Because /dev/random is filled

    from user-generated actions, the read may block and may only

    return a single random byte at a time. */

    do {

        int bytes_read;

        bytes_read = read(dev_random_fd, next_random_byte, bytes_to_read);

        bytes_to_read -= bytes_read;

        next_random_byte += bytes_read;

    } while (bytes_to_read > 0);

    /* Compute a random number in the correct range. */
    //close(dev_random_fd);
    return min + (random_value % (max - min + 1));

}





int getrandnumbers(char* randnumbers, int bytenumbers){  
        static int aaa = bytenumbers;
        char buff[1024] = { 0 };
        printf("inner, randnumbers'addr :%p\n",randnumbers);

        int i = 1;
        while (i < 125)
        {
            i++;
            int a;
            //srand((unsigned)time(NULL) + aaa);
            //a = rand();//4  3e2c6f9d
           // printf("random %x\n", a);
            //aaa++;

            a = random_number(0, 100 * 100);
            //printf("i:%d,buff:%s\n", i, buff);
            sprintf((char*)buff, "%s%x", (char*)buff, a);
        }
        //    strcpy(randnumbers, (char*)buff, bytenumbers);
        memcpy(randnumbers, buff, bytenumbers);

       // printf("buff:%s\nrandom:%s\n", (char*)buff, randnumbers);
    
        //printf("inner  randnumbers 's addr :%p\n", &randnumbers);

        return 0;
}


/*
 * Class:     com_rongan_PSINativeRA
 * Method:    getRandomString
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_rongan_PSINativeRA_getRandomString
(JNIEnv* env, jclass cls, jint randomLen) {

    printf("get random\n");
    // char* randomString = getrandnumbers(randomLen); 
    // printf("\n\n");
    char* randnumbers = (char*)malloc(randomLen + 1);
    memset(randnumbers, 0, randomLen + 1);
        printf("out, randnumbers'addr :%p\n",randnumbers);

   // char** tmpRandom =(char**) getrandnumbers(randnumbers, randomLen);
    getrandnumbers(randnumbers, randomLen);

   printf("randnumbers:%s\n", randnumbers);
  //  printf("tmpRandom:%p\n", tmpRandom);

 //   printf("*tmpRandom:%p\n", *tmpRandom);
   // char* randomString = *tmpRandom;
  //  printf("randomString 's address:%p  \n  ", randomString);
    //printf("randomString 's address:%p  \n  ", randomString);
  //  printf("\n\n");


    //printf("randomString:%s\n", randomString);
    jstring  pointString = env->NewStringUTF(randnumbers);
    free(randnumbers);
    return pointString;


}

/*
 * Class:     com_rongan_PSINativeRA
 * Method:    disorderStrings
 * Signature: ([Ljava/lang/String;[Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_rongan_PSINativeRA_disorderStrings
(JNIEnv* env, jclass cls, jobjectArray inStrings, jobjectArray outStrings) {


}
/*
 * Class:     com_rongan_PSINativeRA
 * Method:    data2Point
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_rongan_PSINativeRA_data2Point
(JNIEnv* env , jclass cls , jstring dataString) {
    //printf("data to point Java_com_rongan_PSINativeRA_data2Point\n");
    if (m_util == NULL)
    {
        m_util = new RAPSIUtilOpenSSL();
    }

    char* data = (char*)env->GetStringUTFChars(dataString, NULL);
    char point[256] = { 0 };

    m_util->data2Point(data, point);
   jstring  pointString = env->NewStringUTF(point);
   strcpy(data, "");
    env->ReleaseStringUTFChars(dataString, data);

   return pointString;

}

/*
 * Class:     com_rongan_PSINativeRA
 * Method:    pointBlindWithRA
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_rongan_PSINativeRA_pointBlindWithRA
(JNIEnv*env , jclass cls , jstring pointString, jstring factorString) {
    if (m_util == NULL)
    {
        m_util = new RAPSIUtilOpenSSL();
    }
    char* point = (char*)env->GetStringUTFChars(pointString, NULL);
    char* factor = (char*)env->GetStringUTFChars(factorString, NULL);
    char blind[256] = { 0 };
    m_util->pointBlindRA(point, factor, blind);
    jstring  blindString = env->NewStringUTF(blind);
     
    strcpy(point, "");
    strcpy(factor, "");
 env->ReleaseStringUTFChars(pointString, point);
 env->ReleaseStringUTFChars(factorString, factor);

    return blindString;
}

/*
 * Class:     com_rongan_PSINativeRA
 * Method:    getInverseRA
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_rongan_PSINativeRA_getInverseRA
(JNIEnv* env , jclass cls , jstring raString) {
    if (m_util == NULL)
    {
        m_util = new RAPSIUtilOpenSSL();
    }
    char* ra = (char*)env->GetStringUTFChars(raString, NULL);
    char ra_1[256] = { 0 };
    m_util->getInverseRA(ra, ra_1);

    jstring inverseString = env->NewStringUTF(ra_1);

    strcpy(ra, "");
 env->ReleaseStringUTFChars(raString, ra);

    return inverseString;

}
/*
 * Class:     com_rongan_PSINativeRA
 * Method:    sm3Hash
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_rongan_PSINativeRA_sm3Hash
(JNIEnv*env , jclass cls , jstring dataString ) {

    if (m_util == NULL)
    {
        m_util = new RAPSIUtilOpenSSL();
    }
    char* data = (char*)env->GetStringUTFChars(dataString, NULL);
    char hash[256] = { 0 };
    m_util->sm3Hash(data, hash);
   jstring hashString = env->NewStringUTF(hash);

   strcpy(data, "");

    env->ReleaseStringUTFChars(dataString, data);

   return hashString;
}
 
void jarray2Array(JNIEnv *env, jobjectArray jarray,int  jcount , char ** charArray) {
// FILE* pFile = fopen(dFile, "a");

    for (int  i = 0; i < jcount; i++)
    {
        jstring jobject =(jstring) env->GetObjectArrayElement(jarray, i);
        char* ctmp =(char*) env->GetStringUTFChars(jobject,NULL);
        char* tmp = (char*)malloc(strlen(ctmp) + 1);
	strcpy(tmp,ctmp);
        charArray[i] = tmp; 

         
        env->ReleaseStringUTFChars(jobject, ctmp);

//    write_log(pFile, "jni jarray2Array tmp :%s\n",ctmp );
    }

//    fclose(pFile);
} 
void charArray2Jarray(JNIEnv* env, char** cArray, int count, jobjectArray jarray) {

    for (int  i = 0; i < count; i++)
    {
        char* tmp = cArray[i];  

        jstring obj = env->NewStringUTF(tmp);
        env->SetObjectArrayElement(jarray, i, obj);

    }
}

void freeCharArray(char** carray, int count) {
    for (int i = 0; i < count ; i++)
    {
        free(carray[i]);
    }
}

/*
 * Class:     com_rongan_PSINativeRA
 * Method:    getIntersect
 * Signature: ([Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_rongan_PSINativeRA_getIntersect
(JNIEnv*env , jclass cls , jobjectArray clientsArray, jobjectArray serversArray, jobjectArray intersectArray) {


    if (m_util == NULL)
    {
        m_util = new RAPSIUtilOpenSSL();
    }

    int client_count = env->GetArrayLength(clientsArray);
    char** clients = (char**)malloc(sizeof(char*) * client_count);
    jarray2Array(env, clientsArray, client_count, clients);

    //cout << "client_count: "<<client_count << endl;

    int server_count = env->GetArrayLength(serversArray);
    char** servers = (char**)malloc(sizeof(char*) * server_count);
    jarray2Array(env, serversArray, server_count, servers);

    //cout <<"server_count: "<< server_count << endl;

    int inter_count = client_count;

    if (server_count > client_count)
    {
        inter_count = server_count;
    }
    int inter_count1 = inter_count;

    //cout<<"##############   222    inter_count1: " << inter_count1 << endl;

#ifdef DebugRA
    ralog(dFile, " server count:%d,  clinet count:%d\n", server_count, client_count);
    ralog(dFile, "jni interset  count:%d\n", inter_count);

#endif // DebugRA

    char** intersect = (char**)malloc(sizeof(char*) * inter_count);
    if (intersect == NULL)
    {
        printf("error intersect == null\n ");

    }
    else
    {
        printf("intersect:%p\n", intersect);
    }
    for (int i = 0; i < inter_count; i++) {
        intersect[i] = (char*)malloc(256);
    }


#ifdef DebugRA

    ralog(dFile, "jni get Interset 00 clients %s ,%d\n", clients[0], client_count);
    ralog(dFile, "jni get Interset 00 servers %s ,%d\n", servers[0], server_count);
    ralog(dFile, "jni get Interset 00 interset %s ,%d\n", intersect[0], inter_count);
#endif // DebugRA
   /* printf("intersect:%p\n  ", intersect);

    printf("clients:%p\n    ", clients);
    printf("servers:%p\n", servers);*/
    m_util->raGetIntersect(clients, client_count, servers, server_count, (char**)intersect, &inter_count);

    cout << "inter_count: " << inter_count << endl;
#ifdef DebugRA
    ralog(dFile, "raGetIntersec success count:%d\n", inter_count);
    ralog(dFile, "raGetIntersec success intersect:%s\n", intersect[0]);

#endif // DebugRA



   /* cout <<"intersect:"<< hex << intersect << ",*intersect:" << *intersect <<",**intersect:"<<**intersect << endl;
    printf("*intersect:%sintersect[0]%s\n", *intersect, intersect[0]);*/

    charArray2Jarray(env, intersect, inter_count, intersectArray);

    //ͷ
    freeCharArray(intersect, inter_count1);
    free(intersect);
    freeCharArray(clients, client_count);
    free(clients);
    freeCharArray(servers, server_count);
    free(servers);


    
     return (jint)inter_count;
}

 
