//=======================================================================
// Copyright abeinoe 2015.
// Distributed under the MIT License.
// (See accompanying file LICENSE or copy at
//  http://opensource.org/licenses/MIT)
//=======================================================================

#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "pattimura.h"
#include <time.h>

int main(void)
{
    PATTIMURA_Context ctx;
    unsigned char cipherKey[16];
    unsigned char plain[16], cipher[16];
    long i;

    printf("################################################\n");
    printf("#########  BEGIN ECB/128 Test Vector  ##########\n");
    printf("################################################\n\n");

    printf("################################################");
    memset(cipherKey, 0, 16);
    memset(plain, 0, 16);

    printCharArray(cipherKey, 16, "seed:");
    printCharArray(plain, 16, "plain:");
    PATTIMURA_Open(&ctx, cipherKey, 128, PATTIMURA_ECB_ENC, PATTIMURA_default_userbox);
    PATTIMURA_EncryptDecript(&ctx, cipher, plain, 1);
    printCharArray(cipher, 16, "cipher:");
    printf("################################################\n\n");

    printf("################################################");
    memset(cipherKey, 0, 16);
    memset(plain, 0xFF, 16);

    printCharArray(cipherKey, 16, "seed:");
    printCharArray(plain, 16, "plain:");
    PATTIMURA_Open(&ctx, cipherKey, 128, PATTIMURA_ECB_ENC, PATTIMURA_default_userbox);
    PATTIMURA_EncryptDecript(&ctx, cipher, plain, 1);
    printCharArray(cipher, 16, "cipher:");
    printf("################################################\n\n");

    printf("################################################");
    memset(cipherKey, 0xFF, 16);
    memset(plain, 0, 16);

    printCharArray(cipherKey, 16, "seed:");
    printCharArray(plain, 16, "plain:");
    PATTIMURA_Open(&ctx, cipherKey, 128, PATTIMURA_ECB_ENC, PATTIMURA_default_userbox);
    PATTIMURA_EncryptDecript(&ctx, cipher, plain, 1);
    printCharArray(cipher, 16, "cipher:");
    printf("################################################\n\n");

    printf("################################################");
    memset(cipherKey, 0xFF, 16);
    memset(plain, 0xFF, 16);

    printCharArray(cipherKey, 16, "seed:");
    printCharArray(plain, 16, "plain:");
    PATTIMURA_Open(&ctx, cipherKey, 128, PATTIMURA_ECB_ENC, PATTIMURA_default_userbox);
    PATTIMURA_EncryptDecript(&ctx, cipher, plain, 1);
    printCharArray(cipher, 16, "cipher:");
    printf("################################################\n\n");

    printf("################################################\n");
    printf("##########  END ECB/128 Test Vector  ###########\n");
    printf("################################################\n\n");

    return 0;
}
