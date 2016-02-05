/* NHASH.C
   Implementation of N-Hash as a function. 
   Modifications Copyright 1994 Willis E. Howard, III
*/

#include <stdio.h>
#include "nhash.h"

/* function prototypes */
static void encrypt (unsigned char *, unsigned char *);
static unsigned char sbox (unsigned char);

/* local working arrays */
static unsigned char X1[16];
static unsigned char X2[16];

/*
    hash128() uses the NHASH algorithm to operate on a
    count*16 byte input array of unsigned char type.  The 16
    byte init array of unsigned char type can have any initial
    values.  The 16 byte output array of unsigned char type will
    contain the results of the hash.

    If count<=0 then the output is set equal to the input.
*/

void
hash128 (int count,
         unsigned char *input,
         unsigned char *init,
         unsigned char *output)
{
    int i;
    int loop;
    unsigned char message[16];
    unsigned char result[16];

    for (i = 0; i < 16; i++)
    {
        X2[i] = init[i];                         /* local copy of init */
        result[i] = input[i];                    /* setup return if count<=0 */
    }

    for (loop = 0; loop < count; loop++)
    {
        for (i = 0; i < 16; i++)
            message[i] = input[16 * loop + i];

        encrypt (message, result);

        for (i = 0; i < 16; i++)
            X2[i] = result[i];
    }

    for (i = 0; i < 16; i++)                     /* clear local data */
    {                                            /* and set return value */
        output[i] = result[i];
        X1[i] = 0;
        X2[i] = 0;
        result[i] = 0;
        message[i] = 0;
    }
}

static void
encrypt (unsigned char *data, unsigned char *output)
{
    unsigned char block[16];
    unsigned char work[4];
    unsigned char V;
    register int loop;
    register int i;

    for (i = 0; i < 16; i++)
        X1[i] = data[i];

    for (i = 0; i < 8; i++)
        block[i] = X2[i] ^ X1[i + 8] ^ 0xaa;
    for (i = 0; i < 8; i++)
        block[i + 8] = X2[i + 8] ^ X1[i] ^ 0xaa;

    V = 0;
    for (loop = 0; loop < 8; loop++)
    {
        for (i = 0; i < 4; i++)
            work[i] = block[i] ^ X1[i];

        /* P1 */

        ++V;
        work[3] ^= V;
        work[1] ^= work[0];
        work[2] ^= work[3];
        work[1] = sbox ((unsigned char) (work[1] + work[2] + 1));
        work[2] = sbox ((unsigned char) (work[2] + work[1]));
        work[0] = sbox ((unsigned char) (work[0] + work[1]));
        work[3] = sbox ((unsigned char) (work[3] + work[2] + 1));

        for (i = 0; i < 4; i++)
            work[i] ^= block[i + 4];
        for (i = 0; i < 4; i++)
            block[i + 12] ^= work[i];
        for (i = 0; i < 4; i++)
            work[i] ^= X1[i + 4];

        /* P2 */

        ++V;
        work[3] ^= V;
        work[1] ^= work[0];
        work[2] ^= work[3];
        work[1] = sbox ((unsigned char) (work[1] + work[2] + 1));
        work[2] = sbox ((unsigned char) (work[2] + work[1]));
        work[0] = sbox ((unsigned char) (work[0] + work[1]));
        work[3] = sbox ((unsigned char) (work[3] + work[2] + 1));

        for (i = 0; i < 4; i++)
            block[i + 8] ^= work[i] ^ block[i];

        /******************************/

        for (i = 0; i < 4; i++)
            work[i] = block[i + 8] ^ X1[i + 8];

        /* P3 */

        ++V;
        work[3] ^= V;
        work[1] ^= work[0];
        work[2] ^= work[3];
        work[1] = sbox ((unsigned char) (work[1] + work[2] + 1));
        work[2] = sbox ((unsigned char) (work[2] + work[1]));
        work[0] = sbox ((unsigned char) (work[0] + work[1]));
        work[3] = sbox ((unsigned char) (work[3] + work[2] + 1));

        for (i = 0; i < 4; i++)
            work[i] ^= block[i + 12];
        for (i = 0; i < 4; i++)
            block[i + 4] ^= work[i];
        for (i = 0; i < 4; i++)
            work[i] ^= X1[i + 12];

        /* P4 */

        ++V;
        work[3] ^= V;
        work[1] ^= work[0];
        work[2] ^= work[3];
        work[1] = sbox ((unsigned char) (work[1] + work[2] + 1));
        work[2] = sbox ((unsigned char) (work[2] + work[1]));
        work[0] = sbox ((unsigned char) (work[0] + work[1]));
        work[3] = sbox ((unsigned char) (work[3] + work[2] + 1));

        for (i = 0; i < 4; i++)
            block[i] ^= work[i] ^ block[i + 8];
    }

    for (i = 0; i < 16; i++)
        output[i] = block[i] ^ X1[i] ^ X2[i];
}

static unsigned char
sbox (unsigned char data)
{
    union
    {
        unsigned int DATA;
        struct
        {
            unsigned char low;
            unsigned char high;
        } reg;
    } s;

    s.reg.high = 0;
    s.reg.low = data;
    s.DATA <<= 2;
    return (s.reg.high | s.reg.low);
}

#ifdef TEST

static unsigned char MESSAGE[32] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

static unsigned char INITIAL[16] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static unsigned char INITIAL2[16] =
{
    0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52,
    0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25};

static unsigned char OUT[16];

static int BL = 2;

void
main()
{
    int i;

    hash128( BL, MESSAGE, INITIAL, OUT);

    printf ("Test Output of N-Hash\n");
    for (i = 0; i < 16; i++)
        printf (" %02X", OUT[i]);

    hash128( BL, MESSAGE, INITIAL2, OUT);

    printf("\n");
    for (i = 0; i < 16; i++)
        printf (" %02X", OUT[i]);
    printf("\n");
}

/* output:
           6a 98 56 20 b4 41 e3 b4 68 03 17 d9 5c 20 97 66 
           93 71 0a 64 64 2b 87 b4 72 0f 8c 11 09 0b ff 72
*/

#endif

