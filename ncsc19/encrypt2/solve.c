#include <stdio.h>
#include <sodium.h>
#include <string.h>

char* xor(char *inn, char *key){
    char tmp[80];
    strncpy(tmp, inn, 64);
    for(int i = 0; i < 64; i++) {
        tmp[i] = inn[i] ^ key[i];
    }

    printf("%s\n", tmp);
}

int main(int agrc, const char **argv) {
	
    	unsigned char salt[0x12];
	FILE *salt_stream = fopen("salt", "r");
	size_t salt_size = fread(salt, sizeof(char), 16, salt_stream);

	unsigned char enc[64];
	FILE *enc_stream = fopen("enc", "r");
	size_t enc_size = fread(&enc, sizeof(char), 64, enc_stream);


	if( sodium_init() < 0) {
		printf("Sodium init failed");
		exit(1);
	}

    	unsigned char key[enc_size];
	unsigned char pw[3];

    	for(int i = 100; i < 1000; i++) {
        	sprintf(pw, "%d", i);
        	if( crypto_pwhash
                	(key, enc_size, pw, 3, salt,
                	crypto_pwhash_OPSLIMIT_INTERACTIVE, 0x4000000, 
                	2) != 0
      		){
            		printf("OOM\n");
        	}
        	
		xor(enc, key);
    }
}



