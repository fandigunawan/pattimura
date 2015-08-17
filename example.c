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
    unsigned char plain[16], cipher[16], decrypted[16];
    clock_t t0, t1, elapsed;
    long i;

    memset(cipherKey, 0, 16);
    memset(plain, 0, 16);
    memset(cipher, 0, 16);

    printCharArray(plain, 16, "plain:");
    PATTIMURA_Open(&ctx, cipherKey, 128, PATTIMURA_ECB_ENC, PATTIMURA_default_userbox);
    PATTIMURA_EncryptDecript(&ctx, cipher, plain, 1);
    printCharArray(cipher, 16, "cipher:");
    PATTIMURA_Open(&ctx, cipherKey, 128, PATTIMURA_ECB_DEC, PATTIMURA_default_userbox);
    PATTIMURA_EncryptDecript(&ctx, decrypted, cipher, 1);
    printCharArray(decrypted, 16, "decrypted:");

    if(memcmp(plain, decrypted, 16) == 0)
        printf("\nberhasil!\n");
    else
        printf("\ngagal!\n");

    return 0;
}
