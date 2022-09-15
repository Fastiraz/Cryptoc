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

void md5func(char *string){
    //char string[255] = "Hello World";
    char md5_hash[2*MD5_DIGEST_LENGTH+1] = "";
    md5_hash_from_string(string, md5_hash);
    printf("%s\n", md5_hash);
}
/*==================================================================================*/




/*==================================================================================*/
void md4func(char *text){
    //const char *text = "Hello";

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
void sha512func(char *s){
    //const char s[131] = "password";
	unsigned char *d = SHA512(s, strlen(s), 0);

	int i;
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha384func(char *s){
    //const char s[131] = "password";
	unsigned char *d = SHA384(s, strlen(s), 0);

	int i;
	for (i = 0; i < SHA384_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha256func(char *s){
    //const char s[131] = "password";
	unsigned char *d = SHA256(s, strlen(s), 0);

	int i;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha224func(char *s){
    //const char s[131] = "password";
	unsigned char *d = SHA224(s, strlen(s), 0);

	int i;
	for (i = 0; i < SHA224_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




/*==================================================================================*/
void sha1func(char *s){
    //const char s[131] = "password";
	unsigned char *d = SHA1(s, strlen(s), 0);

	int i;
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		printf("%02x", d[i]);
	putchar('\n');
}
/*==================================================================================*/




int main(int argc, char **argv)
{
    if(argc < 3){
      if(strcmp("-h", argv[1]) == 0){
          printf("\n"
          "\nHash algo:"
          "\n   md4"
          "\n   md5"
          "\n   sha1"
          "\n   sha224"
          "\n   sha256"
          "\n   sha384"
          "\n   sha512\n\n");
      }
      else{
          printf("\nMissing arg.\n\n");
      }
    }
    else if(argc == 3){
        if(strcmp("md5", argv[1]) == 0){
            md5func(argv[2]);
        }
        else if(strcmp("sha256", argv[1]) == 0){
            sha256func(argv[2]);
        }
        else if(strcmp("sha1", argv[1]) == 0){
            sha1func(argv[2]);
        }
        else if(strcmp("md4", argv[1]) == 0){
            md4func(argv[2]);
        }
        else if(strcmp("sha512", argv[1]) == 0){
            sha512func(argv[2]);
        }
        else if(strcmp("sha224", argv[1]) == 0){
            sha224func(argv[2]);
        }
        else if(strcmp("sha384", argv[1]) == 0){
            sha384func(argv[2]);
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
