/* lucifr_c.c */
/* LUCIFER cipher: 128 bit key, 128 bit block in CBC mode */
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F LUCIFR_C.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include "crypt.h"
#include "hex.h"
#include "lucifer.h"
#include "nhash.h"

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file.
*/

static int key_defined = 0;                      /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static short mode = EN;
static char key_string[257];
static char actual_key[16];

static void process_key (char *, char *);
static void makekey (char *, char *);

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[] =
{
    "CIPHER",
    "      The program uses the LUCIFER cipher as developed by IBM.",
    "      A 128 bit key is used to encrypt a 128 bit block.",
    "      CBC mode is used.  The simple file name of the source file",
    "      on encryption and destination file on decrytion is used as",
    "      the initialization vector. The simple file name of the",
    "      decrypted file must be the same as the simple file name",
    "      of the original file.  Files with less than 16 bytes are",
    "      not secure.",
    "",
    "      Use the -d option for decryption.",
    "",
    "KEY",
    "      The key is an ASCII string.  If you use more than one",
    "      word in the phrase and give the key with the -k option",
    "      on the command line, place the phrase within quotes.",
    "      At most 256 characters will be used in the phrase.",
    "      If the string evaluates to exactly 16 hex bytes such as",
    "      \"F0AB 457E 006C E4AA 0DB3 57E3 AB52 2CC4\" with spaces",
    "      ignored, then that exact 128 bit key is used.  Otherwise,",
    "      the ASCII characters are hashed to form a 128 bit key.",
    "",
    "      If a key file exists, only the first line is read, and",
    "      it is used as the key phrase.",
    "",
    "      If there is no key phrase, you will be prompted for one.",
    NULL
};

char **
crypt_help ()
{
    return cipher_doc;                        /* return a pointer to the help strings */
}

/*
   crypt_key:
   Get the key from the passed string (that may be a file name in some
   implementations) or from a key file name.  Return 0 on success but
   exit on error.
*/

int
crypt_key (int key_type, char *key_text)
{
    int i;
    char *s;
    FILE *fp;

    for (i=0; i<257; i++)                        /* initialize key string */
        key_string[i] = '\0';

    if (key_type == KEY_FILE)                    /* a file name has been given */
    {
        if ((fp = fopen (key_text, "r")) == NULL)
        {
            key_defined = 0;
            return 0;
        }
        s = key_string;
        i = 0;
        for (;;)
        {
            *s = fgetc (fp);
            if ((*s == '\n') || (*s == EOF))
            {
                *s = '\0';
                if (i == 0)
                {
                    key_defined = 0;
                    break;
                }
                else
                {
                    process_key (key_string, actual_key);
                    key_defined = 1;
                    break;
                }
            }
            else if (i == 255)
            {
                *++s = '\0';
                process_key (key_string, actual_key);
                key_defined = 1;
                break;
            }
            s++;
            i++;
        }
        fclose (fp);
        return 0;
    }
    else if (key_type == KEY_IMMEDIATE)          /* a key string has been given */
    {
        if (!strcmp (key_text, "?"))             /* prompt for key */
        {
            printf ("Key: ");                    /* input key from stdin */
            s = key_string;
            i = 0;
            for (;;)
            {
                *s = fgetc (stdin);
                if ((*s == '\n') || (*s == EOF))
                {
                    *s = '\0';
                    process_key (key_string, actual_key);
                    key_defined = 1;
                    break;
                }
                else if (i == 255)
                {
                    *++s = '\0';
                    process_key (key_string, actual_key);
                    key_defined = 1;
                    break;
                }
                s++;
                i++;
            }
        }
        else
            /* copy string up to 256 characters */
        {
            strncpy (key_string, key_text, 256);
            key_string[256] = '\0';
            process_key (key_string, actual_key);
            key_defined = 1;
        }
        return 0;
    }
    fprintf (stderr, "Error getting key\n");
    exit (1);
}

/*
   crypt_key_erase:
   If a local copy of the key has been made, erase it from memory.
   This increases security that the key can not be obtained from
   an examination of memory.
*/

void
crypt_key_erase ()
{
    int i;

    for (i = 0; i < 257; i++)
        key_string[i] = '\0';

    for (i=0; i<16; i++)
        actual_key[i] = '\0';

    key_defined = 0;

    return;
}

/*
    crypt_select:
    If encryption and decryption require different ciphers,
    this routine defines the direction.  Valid choices are
    ENCRYPTION_SELECT and DECRYPTION_SELECT.
*/

int
crypt_select (int selection)
{
    if (selection == ENCRYPTION_SELECT)
    {
        if (encrypt_or_decrypt == DECRYPTION_SELECT)
        {
            encrypt_or_decrypt = ENCRYPTION_SELECT;
            mode = EN;
            if (key_defined)                     /* if we have a key, recalculate */
                process_key (key_string, actual_key);
        }
    }

    if (selection == DECRYPTION_SELECT)
    {
        if (encrypt_or_decrypt == ENCRYPTION_SELECT)
        {
            encrypt_or_decrypt = DECRYPTION_SELECT;
            mode = DE;
            if (key_defined)                     /* if we have a key, recalculate */
                process_key (key_string, actual_key);
        }
    }

    return encrypt_or_decrypt;
}

/*
    crypt_file:
    encrypt or decrypt the source to the destination file.
    Do not exit from this routine.  Return 0 on success
    and return 1 on error.  Use an fprintf(stderr, ... ) to
    report the nature of the error and close any open files.
    This allows the main routine to do some cleanup before
    exiting.
*/

int
crypt_file (char *source, char *dest)
{
    int i;
    int count = 16;                               /* block size */
    char fPath[_MAX_PATH];
    char sDrive[_MAX_DRIVE];
    char sDir[_MAX_DIR];
    char sFname[_MAX_FNAME];
    char sExt[_MAX_EXT];
    char buffer[16];
    char cbc[16];
    char fcbc[16];
    char seed[16];
    char *path;
    FILE *infile;
    FILE *outfile;

    while (!key_defined)
        crypt_key (KEY_IMMEDIATE, "?");

    if ((infile = fopen (source, "rb")) == NULL)
    {
        fprintf (stderr, "Can not open %s for reading.\n", source);
        return 1;
    }

    if ((outfile = fopen (dest, "wb")) == NULL)
    {
        fprintf (stderr, "Can not open %s for writing.\n", dest);
        fclose (infile);
        return 1;
    }

    if (encrypt_or_decrypt == ENCRYPTION_SELECT)
        strcpy(fPath, source);
    else
        strcpy(fPath, dest);
    
    path = _fullpath(NULL, fPath, 0);
    _splitpath( path, sDrive, sDir, sFname, sExt );
    free(path);

    for (i = 0; i < count; i++)
    {
        buffer[i] = (char) 0x20;                 /* text files padded with spaces */
        cbc[i] = fcbc[i] = seed[i] = '\0';       /* constant initialization vector */
    }

    for (i=0; i < 8; i++)                        /* copy up to 8 letters from simple file name */
    {
        if (sFname[i] == '\0')
            break;
        cbc[i] = cbc[i+8] = fcbc[i] = fcbc[i+8] = toupper(sFname[i]);
    }

    while (count = fread (buffer, sizeof (char), count, infile))
    {
        if (encrypt_or_decrypt == ENCRYPTION_SELECT)        
        {
            for (i=0; i<16; i++)
                buffer[i] ^= cbc[i];
            if (count == 16)
                lucifer (buffer);
            else
            {
                lucifer (cbc);
                for (i=0; i<16; i++)
                    buffer[i] ^= cbc[i];
            }
            for (i=0; i<16; i++)
                cbc[i] = buffer[i];
        }
        else
        {
            for (i=0; i<16; i++)
                cbc[i] = buffer[i];
            if (count == 16)
                lucifer (buffer);
            else
            {
                crypt_select (ENCRYPTION_SELECT);
                for (i=0; i<16; i++)
                    seed[i] = fcbc[i];
                lucifer (seed);
                crypt_select (DECRYPTION_SELECT);
                for (i=0; i<16; i++)
                    buffer[i] ^= seed[i];
            }
            for (i=0; i<16; i++)
            {
                buffer[i] ^= fcbc[i];
                fcbc[i] = cbc[i];
            }
        }

        if (count != fwrite (buffer, sizeof (char), count, outfile))
        {
            fprintf (stderr, "Could not write to %s\n", source);
            fclose (infile);
            fclose (outfile);
            return 1;
        }
        else
        {
            for (i = 0; i < 16; i++)
                buffer[i] = (char) 0x20;
        }
    }

    for (i=0; i<16; i++)
        cbc[i] = fcbc[i] = seed[i] = '\0';

    fclose (infile);
    fclose (outfile);
    return 0;
}

/* Convert a string to a key */

static void
process_key (char *s, char *key)
{
    char string[257];
    int i;
    int j;
    int shift = 1;
    int value = 0;
    int hex_count = 0;
    int nonhex_count = 0;
    int white_count = 0;

    /* zero string */
    for (i=0; i<256; i++)
        string[i] = '\0';

    /* check if a hex number or ascii string was entered */
    for (i = 0; (i < 256) && *s; i++)
    {
        string[i] = *s++;
        if (ishex (string[i]))
            hex_count++;
        else if (string[i] == ' ')
            white_count++;
        else
            nonhex_count++;
    }
    string[i] = '\0';

    /* either convert hex number or process ascii string */
    if (hex_count == 32 && nonhex_count == 0)
    {
        hex_count = 0;
        for (i = 0; string[i] != '\0'; i++)
        {
            if ((value = hextoint (string[i])) != -1)
            {
                if (shift)
                {
                    key[hex_count >> 1] = (unsigned char) value << 4;
                    hex_count++;
                    shift = 0;
                }
                else
                {
                    key[hex_count >> 1] += (unsigned char) value;
                    hex_count++;
                    shift = 1;
                }
            }
            string[i] = '\0';
        }
    }
    else
    {
        makekey (string, key);
    }

    /* select the key for use */
    loadkey (key, mode);
}

static void 
makekey(char * s, char * key)
{
    int i;
    int block_count;
    unsigned char array[16];
    
    unsigned char init[16] = 
    {  0xa7, 0x6b, 0x32, 0xd4, 0x29, 0xa3, 0xe2, 0x2c, 
       0x97, 0x65, 0x12, 0x0e, 0x0d, 0xf1, 0xf5, 0x78
    } ;

    if (!*s)
        block_count = 0;
    else
    {
        block_count = ( (strlen( s ) - 1 ) / 16 ) +1;
        if (block_count > 16)
            block_count = 16;
    }

    hash128 (block_count, s, init, array);

    for (i=0; i<16; i++)
    {
        key[i] = array[i];
        array[i] = '\0';
    }
}

/* LUCIFER is a cryptographic cipher developed by IBM in the early
 *      seventies.  It was a predecessor of the DES, and is much simpler
 *      than that cipher.  In particular, it has only two substitution
 *      boxes.  It does, however, use a 128 bit key and operates on
 *      sixteen unsigned char data blocks...
 *
 *      This implementation of LUCIFER was crafted by Graven Cyphers at the
 *      University of Toronto, Canada, with programming assistance from
 *      Richard Outerbridge.  It is based on the FORTRAN routines which
 *      concluded Arthur Sorkin's article "LUCIFER: A Cryptographic Algorithm",
 *      CRYPTOLOGIA, Volume 8, Number 1, January 1984, pp22-42.  The interested
 *      reader should refer to that article rather than this program for more
 *      details on LUCIFER.
 *
 *      These routines bear little resemblance to the actual LUCIFER cipher,
 *      which has been severely twisted in the interests of speed.  They do
 *      perform the same transformations, and are believed to be UNIX portable.
 *      The package was developed for use on UNIX-like systems lacking crypto
 *      facilities.  They are not very fast, but the cipher is very strong.
 *      The routines in this file are suitable for use as a subroutine library
 *      after the fashion of crypt(3).  When linked together with applications
 *      routines they can also provide a high-level cryptographic system.
 *
 *      -DENHANCE : modify LUCIFER by changing the key schedule and performing
 *              an "autokeyed" encryption.  These may improve the cipher.
 */

#ifndef DE
#define DE      1                                /* for separate compilation    */
#endif

static unsigned char Dps[64] =
{                                                /* Diffusion Pattern schedule  */
    4, 16, 32, 2, 1, 8, 64, 128, 128, 4, 16, 32, 2, 1, 8, 64,
    64, 128, 4, 16, 32, 2, 1, 8, 8, 64, 128, 4, 16, 32, 2, 1,
    1, 8, 64, 128, 4, 16, 32, 2, 2, 1, 8, 64, 128, 4, 16, 32,
    32, 2, 1, 8, 64, 128, 4, 16, 16, 32, 2, 1, 8, 64, 128, 4};

/* Precomputed S&P Boxes, Two Varieties */
static unsigned char TCB0[256] =
{
    87, 21, 117, 54, 23, 55, 20, 84, 116, 118, 22, 53, 85, 119, 52, 86,
    223, 157, 253, 190, 159, 191, 156, 220, 252, 254, 158, 189, 221, 255, 188, 222,
    207, 141, 237, 174, 143, 175, 140, 204, 236, 238, 142, 173, 205, 239, 172, 206,
    211, 145, 241, 178, 147, 179, 144, 208, 240, 242, 146, 177, 209, 243, 176, 210,
    215, 149, 245, 182, 151, 183, 148, 212, 244, 246, 150, 181, 213, 247, 180, 214,
    95, 29, 125, 62, 31, 63, 28, 92, 124, 126, 30, 61, 93, 127, 60, 94,
    219, 153, 249, 186, 155, 187, 152, 216, 248, 250, 154, 185, 217, 251, 184, 218,
    67, 1, 97, 34, 3, 35, 0, 64, 96, 98, 2, 33, 65, 99, 32, 66,
    195, 129, 225, 162, 131, 163, 128, 192, 224, 226, 130, 161, 193, 227, 160, 194,
    199, 133, 229, 166, 135, 167, 132, 196, 228, 230, 134, 165, 197, 231, 164, 198,
    203, 137, 233, 170, 139, 171, 136, 200, 232, 234, 138, 169, 201, 235, 168, 202,
    75, 9, 105, 42, 11, 43, 8, 72, 104, 106, 10, 41, 73, 107, 40, 74,
    91, 25, 121, 58, 27, 59, 24, 88, 120, 122, 26, 57, 89, 123, 56, 90,
    71, 5, 101, 38, 7, 39, 4, 68, 100, 102, 6, 37, 69, 103, 36, 70,
    79, 13, 109, 46, 15, 47, 12, 76, 108, 110, 14, 45, 77, 111, 44, 78,
    83, 17, 113, 50, 19, 51, 16, 80, 112, 114, 18, 49, 81, 115, 48, 82};

static unsigned char TCB1[256] =
{
    87, 223, 207, 211, 215, 95, 219, 67, 195, 199, 203, 75, 91, 71, 79, 83,
    21, 157, 141, 145, 149, 29, 153, 1, 129, 133, 137, 9, 25, 5, 13, 17,
    117, 253, 237, 241, 245, 125, 249, 97, 225, 229, 233, 105, 121, 101, 109, 113,
    54, 190, 174, 178, 182, 62, 186, 34, 162, 166, 170, 42, 58, 38, 46, 50,
    23, 159, 143, 147, 151, 31, 155, 3, 131, 135, 139, 11, 27, 7, 15, 19,
    55, 191, 175, 179, 183, 63, 187, 35, 163, 167, 171, 43, 59, 39, 47, 51,
    20, 156, 140, 144, 148, 28, 152, 0, 128, 132, 136, 8, 24, 4, 12, 16,
    84, 220, 204, 208, 212, 92, 216, 64, 192, 196, 200, 72, 88, 68, 76, 80,
    116, 252, 236, 240, 244, 124, 248, 96, 224, 228, 232, 104, 120, 100, 108, 112,
    118, 254, 238, 242, 246, 126, 250, 98, 226, 230, 234, 106, 122, 102, 110, 114,
    22, 158, 142, 146, 150, 30, 154, 2, 130, 134, 138, 10, 26, 6, 14, 18,
    53, 189, 173, 177, 181, 61, 185, 33, 161, 165, 169, 41, 57, 37, 45, 49,
    85, 221, 205, 209, 213, 93, 217, 65, 193, 197, 201, 73, 89, 69, 77, 81,
    119, 255, 239, 243, 247, 127, 251, 99, 227, 231, 235, 107, 123, 103, 111, 115,
    52, 188, 172, 176, 180, 60, 184, 32, 160, 164, 168, 40, 56, 36, 44, 48,
    86, 222, 206, 210, 214, 94, 218, 66, 194, 198, 202, 74, 90, 70, 78, 82};

static unsigned char Key[16], Pkey[128];
static int P[8] =
{3, 5, 0, 4, 2, 1, 7, 6};
static int Smask[16] =
{128, 64, 32, 16, 8, 4, 2, 1};

void 
lucifer (bytes)
     unsigned char *bytes;                       /* points to a 16-byte array   */
{
    register unsigned char *cp, *sp, *dp;
    register int val, *sbs, tcb, j, i;
    unsigned char *h0, *h1, *kc, *ks;

    h0 = bytes;                                  /* the "lower" half    */
    h1 = &bytes[8];                              /* the "upper" half    */
    kc = Pkey;
    ks = Key;

    for (i = 0; i < 16; i++)
    {
        tcb = *ks++;
        sbs = Smask;
        dp = Dps;
        sp = &h0[8];
#ifdef ENHANCE
        for (j = 0, cp = h1; j < 8; j++)
            tcb ^= *cp++;
#endif
        for (j = 0; j < 8; j++)
        {
            if (tcb & *sbs++)
                val = TCB1[h1[j] & 0377];
            else
                val = TCB0[h1[j] & 0377];
            val ^= *kc++;
            for (cp = h0; cp < sp;)
                *cp++ ^= (val & *dp++);
        }

        /* swap (virtual) halves        */
        cp = h0;
        h0 = h1;
        h1 = cp;
    }

    /* REALLY swap halves       */
    dp = bytes;
    cp = &bytes[8];
    for (sp = cp; dp < sp; dp++, cp++)
    {
        val = *dp;
        *dp = *cp;
        *cp = val;
    }
    return;
}

void 
loadkey (keystr, edf)                            /* precomputes the key schedules       */
     unsigned char *keystr;
     register int edf;
{
    register unsigned char *ep, *cp, *pp;
    register int kc, i, j;
    unsigned char kk[16], pk[16];
    cp = kk;
    pp = pk;
    ep = &kk[16];
    while (cp < ep)
    {
        *cp++ = *keystr;
        for (*pp = i = 0; i < 8; i++)
            if (*keystr & Smask[i])
                *pp |= Smask[P[i]];
        keystr++;
        pp++;
    }
    cp = Key;
    pp = Pkey;
    kc = (edf == DE) ? 8 : 0;
    for (i = 0; i < 16; i++)
    {
        if (edf == DE)
            kc = (++kc) & 017;
#ifdef ENHANCE
        *cp++ = kk[((kc == 0) ? 15 : (kc - 1))];
#else
        *cp++ = kk[kc];
#endif
        for (j = 0; j < 8; j++)
        {
            *pp++ = pk[kc];
            if (j < 7 || (edf == DE))
                kc = (++kc) & 017;
        }
    }
    return;
}

/* lucifer cks # < /dev/null
 *      : 16 bytes      : 32186510 6acf6094 87953eba 196f5a75 :
 *      (-DENHANCE)     : 378cfd5b bd54a07b 28513809 624e6071 :
 *                      (rwo/8412.03.18:10/V5.0)                */
/************************ lucifer *******************************/

