#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>
#include <openssl/evp.h>

#define DIGEST_LENGTH 16


/*==================================================================================*/
void md5_hash_from_string (char *string, char *hash)
{
    int i;
    char unsigned md5[MD5_DIGEST_LENGTH] = {0};

    MD5((const unsigned char *)string, strlen(string), md5);

    for (i=0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(hash + 2*i, "%02x", md5[i]);
    }
}

void md5func(){
    char string[255] = "Hello World";
    char md5_hash[2*MD5_DIGEST_LENGTH+1] = "";
    md5_hash_from_string(string, md5_hash);
    printf("%s\n", md5_hash);
}
/*==================================================================================*/




/*==================================================================================*/
void md4func(){
    const char *text = "Hello";

    unsigned char bytes[DIGEST_LENGTH];

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_md4(), NULL);
    EVP_DigestUpdate(context, text, strlen(text));
    unsigned int digestLength = DIGEST_LENGTH;
    EVP_DigestFinal_ex(context, bytes, &digestLength);#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>
#include <openssl/evp.h>

#define DIGEST_LENGTH 16


/*==================================================================================*/
void md5_hash_from_string (char *string, char *hash)
{
    int i;
    char unsigned md5[MD5_DIGEST_LENGTH] = {0};

    MD5((const unsigned char *)string, strlen(string), md5);

    for (i=0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(hash + 2*i, "%02x", md5[i]);
    }
}

void md5func(){
    char string[255] = "Hello World";
    char md5_hash[2*MD5_DIGEST_LENGTH+1] = "";
    md5_hash_from_string(string, md5_hash);
    printf("%s\n", md5_hash);
}
/*==================================================================================*/




/*==================================================================================*/
void md4func(){
    const char *text = "Hello";

    unsigned char bytes[DIGEST_LENGTH];

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_md4(), NULL);
    EVP_DigestUpdate(context, text, strlen(text));
    unsigned int digestLength = DIGEST_LENGTH;
    EVP_DigestFinal_ex(context, bytes, &digestLength);
    EVP_MD_CTX_free(context);

    char digest[DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < DIGEST_LENGTH; i++) {
        sprintf(&digest[i * 2], "%02x", bytes[i]);
    }

    printf("%s\n", digest);
}
/*==================================================================================*/




/*==================================================================================*/
void sha512func(void){
    const char s[131] = "password";
	unsigned char *d = SHA512(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha384func(void){
    const char s[131] = "password";
	unsigned char *d = SHA384(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA384_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha256func(void){
    const char s[131] = "password";
	unsigned char *d = SHA256(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha224func(void){
    const char s[131] = "password";
	unsigned char *d = SHA224(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA224_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha1func(void){
    const char s[131] = "password";
	unsigned char *d = SHA1(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




int main(int argc, char **argv)
{
    if(argc < 2){
        printf("\nMissing arg.");
    }
    else if(argc == 2){
        if(strcmp("md5", argv[1]) == 0){
            md5func();
        }
        else if(strcmp("sha256", argv[1]) == 0){
            sha256func();
        }
        else if(strcmp("sha1", argv[1]) == 0){
            sha1func();
        }
        else if(strcmp("md4", argv[1]) == 0){
            md4func();
        }
        else if(strcmp("sha512", argv[1]) == 0){
            sha512func();
        }
        else if(strcmp("sha224", argv[1]) == 0){
            sha224func();
        }
        else if(strcmp("sha384", argv[1]) == 0){
            sha384func();
        }
        else if(strcmp("-h", argv[1]) == 0){
            printf("\n"
            "Hash algo:"
            "   md4"
            "   md5"
            "   sha1"
            "   sha224"
            "   sha256"
            "   sha384"
            "   sha512");
        }
        else{
            printf("Invalid arg");
        }
    }
    else{
        printf("To much arg.");
    }
    return 0;
}
    EVP_MD_CTX_free(context);

    char digest[DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < DIGEST_LENGTH; i++) {
        sprintf(&digest[i * 2], "%02x", bytes[i]);
    }

    printf("%s\n", digest);
}
/*==================================================================================*/




/*==================================================================================*/
void sha512func(void){
    const char s[131] = "password";
	unsigned char *d = SHA512(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha384func(void){
    const char s[131] = "password";
	unsigned char *d = SHA384(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA384_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha256func(void){
    const char s[131] = "password";
	unsigned char *d = SHA256(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha224func(void){
    const char s[131] = "password";
	unsigned char *d = SHA224(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA224_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha1func(void){
    const char s[131] = "password";
	unsigned char *d = SHA1(s, strlen(s), 0);
 
	int i;
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




int main(int argc, char **argv)
{
    if(argc < 2){
        printf("\nMissing arg.");
    }
    else if(argc == 2){
        if(strcmp("md5", argv[1]) == 0){
            md5func();
        }
        else if(strcmp("sha256", argv[1]) == 0){
            sha256func();
        }
        else if(strcmp("sha1", argv[1]) == 0){
            sha1func();
        }
        else if(strcmp("md4", argv[1]) == 0){
            md4func();
        }
        else if(strcmp("sha512", argv[1]) == 0){
            sha512func();
        }
        else if(strcmp("sha224", argv[1]) == 0){
            sha224func();
        }
        else if(strcmp("sha384", argv[1]) == 0){
            sha384func();
        }
        else{
            printf("Invalid arg");
        }
    }
    else{
        printf("To much arg.");
    }
    return 0;
}
