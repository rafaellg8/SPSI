/* des3_c.c */
/* DES Outerbridge triple cipher: 192 bit key, 64 bit block with cipher block chaining */
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F DES3_C.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include "crypt.h"
#include "hex.h"
#include "des.h"                                 /* one .h for all DES versions */

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file. 
*/

static int key_defined = 0;                      /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static short mode = EN0;
static char key_string[257];
static char actual_key[24];

void process_key (char *, char *);

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[] =
{
    "CIPHER",
    "      The program uses a triple Data Encryption Standard (DES) cipher.",
    "      A 192 bit key is used to encrypt a 64 bit block with CBC.",
    "      This version uses the Outerbridge implementation.",
    "      Cipher block chaining uses vector initialization preset to the",
    "      simple 8 character file name.  The initialization is given by",
    "      the source file name on encryption, and destination file name",
    "      on decryption.  The simple file name of the decrypted file must",
    "      thus be the same as the simple file name of the original file.",
    "      Encryption is not secure for files with less than 8 bytes.",
    "",
    "      Use the -d option for decryption.",
    "",
    "KEY",
    "      The key is an ASCII string.  If you use more than one",
    "      word in the phrase and give the key with the -k option",
    "      on the command line, place the phrase within quotes.",
    "      At most 256 characters will be used in the phrase.",
    "      If the string evaluates to exactly 24 hex bytes such as",
    "      \"5E2C B347 9AAC 3DAC 53C3 A42B 8C46 1CB5 F0AB 457E 006C E4AA\"",
    "      with spaces ignored, then that exact 192 bit key is used.",
    "      Otherwise, the ASCII characters are hashed to form a 192 bit key.",
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

    process_key (key_string, actual_key);
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
            mode = EN0;
            if (key_defined)                     /* if we have a key, recalculate */
                process_key (key_string, actual_key);
        }
    }

    if (selection == DECRYPTION_SELECT)
    {
        if (encrypt_or_decrypt == ENCRYPTION_SELECT)
        {
            encrypt_or_decrypt = DECRYPTION_SELECT;
            mode = DE1;
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
    int count = 8;                               /* block size */
    char fPath[_MAX_PATH];
    char sDrive[_MAX_DRIVE];
    char sDir[_MAX_DIR];
    char sFname[_MAX_FNAME];
    char sExt[_MAX_EXT];
    char buffer[8];
    char cbc[8];
    char fcbc[8];
    char seed[8];
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

    for (i = 0; i < 8; i++)
    {
        buffer[i] = (char) 0x20;                 /* text files padded with spaces */
        cbc[i] = fcbc[i] = seed[i] = '\0';       /* constant initialization vector */
    }

    for (i=0; i < 8; i++)                        /* copy up to 8 letters from simple file name */
    {
        if (sFname[i] == '\0')
            break;
        cbc[i] = fcbc[i] = toupper(sFname[i]);
    }

    while (count = fread (buffer, sizeof (char), count, infile))
    {
        if (encrypt_or_decrypt == ENCRYPTION_SELECT)        
        {
            for (i=0; i<8; i++)
                buffer[i] ^= cbc[i];
            if (count == 8)
                Ddes ((unsigned char *) buffer, (unsigned char *) buffer);
            else
            {
                Ddes ((unsigned char *) cbc, (unsigned char *) seed);
                for (i=0; i<8; i++)
                    buffer[i] ^= seed[i];
            }
            for (i=0; i<8; i++)
                cbc[i] = buffer[i];
        }
        else
        {
            for (i=0; i<8; i++)
                cbc[i] = buffer[i];
            if (count == 8)
                Ddes ((unsigned char *) buffer, (unsigned char *) buffer);
            else
            {
                crypt_select (ENCRYPTION_SELECT);
                Ddes ((unsigned char *) fcbc, (unsigned char *) seed);
                crypt_select (DECRYPTION_SELECT);
                for (i=0; i<8; i++)
                    buffer[i] ^= seed[i];
            }
            for (i=0; i<8; i++)
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
            for (i = 0; i < count; i++)
                buffer[i] = (char) 0x20;
        }
    }

    for (i=0; i<8; i++)
        cbc[i] = fcbc[i] = seed[i] = '\0';

    fclose (infile);
    fclose (outfile);
    return 0;
}

/* Convert a string to a key and check for weak keys */

void
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
    if (hex_count == 48 && nonhex_count == 0)
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
        make3key (string, key);

    /* select the key for use */
    des3key (key, mode);
}

/* D3DES (V5.09) -
 *
 * A portable, public domain, version of the Data Encryption Standard.
 *
 * Written with Symantec's THINK (Lightspeed) C by Richard Outerbridge.
 * Thanks to: Dan Hoey for his excellent Initial and Inverse permutation
 * code;  Jim Gillogly & Phil Karn for the DES key schedule code; Dennis
 * Ferguson, Eric Young and Dana How for comparing notes; and Ray Lau,
 * for humouring me on.
 *
 * Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.
 *
 * (GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1992.
 */

static void scrunch (unsigned char *, unsigned long *);
static void unscrun (unsigned long *, unsigned char *);
static void desfunc (unsigned long *, unsigned long *);
static void cookey (unsigned long *);

static unsigned long KnL[32] =
{0L};

static unsigned long KnR[32] =
{0L};

static unsigned long Kn3[32] =
{0L};

static unsigned char Df_Key[24] =
{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67};

static unsigned short bytebit[8] =
{
    0200, 0100, 040, 020, 010, 04, 02, 01};

static unsigned long bigbyte[24] =
{
    0x800000L, 0x400000L, 0x200000L, 0x100000L,
    0x80000L, 0x40000L, 0x20000L, 0x10000L,
    0x8000L, 0x4000L, 0x2000L, 0x1000L,
    0x800L, 0x400L, 0x200L, 0x100L,
    0x80L, 0x40L, 0x20L, 0x10L,
    0x8L, 0x4L, 0x2L, 0x1L};

/* Use the key schedule specified in the Standard (ANSI X3.92-1981). */

static unsigned char pc1[56] =
{
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3};

static unsigned char totrot[16] =
{
    1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28};

static unsigned char pc2[48] =
{
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
    22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31};

void
deskey (key, edf)                                /* Thanks to James Gillogly & Phil Karn! */
     unsigned char *key;
     short edf;
{
    register int i,
     j,
     l,
     m,
     n;
    unsigned char pc1m[56],
     pcr[56];
    unsigned long kn[32];

    for (j = 0; j < 56; j++)
    {
        l = pc1[j];
        m = l & 07;
        pc1m[j] = (key[l >> 3] & bytebit[m]) ? 1 : 0;
    }
    for (i = 0; i < 16; i++)
    {
        if (edf == DE1)
            m = (15 - i) << 1;
        else
            m = i << 1;
        n = m + 1;
        kn[m] = kn[n] = 0L;
        for (j = 0; j < 28; j++)
        {
            l = j + totrot[i];
            if (l < 28)
                pcr[j] = pc1m[l];
            else
                pcr[j] = pc1m[l - 28];
        }
        for (j = 28; j < 56; j++)
        {
            l = j + totrot[i];
            if (l < 56)
                pcr[j] = pc1m[l];
            else
                pcr[j] = pc1m[l - 28];
        }
        for (j = 0; j < 24; j++)
        {
            if (pcr[pc2[j]])
                kn[m] |= bigbyte[j];
            if (pcr[pc2[j + 24]])
                kn[n] |= bigbyte[j];
        }
    }
    cookey (kn);
    return;
}

static void
cookey (raw1)
     register unsigned long *raw1;
{
    register unsigned long *cook,
    *raw0;
    unsigned long dough[32];
    register int i;

    cook = dough;
    for (i = 0; i < 16; i++, raw1++)
    {
        raw0 = raw1++;
        *cook = (*raw0 & 0x00fc0000L) << 6;
        *cook |= (*raw0 & 0x00000fc0L) << 10;
        *cook |= (*raw1 & 0x00fc0000L) >> 10;
        *cook++ |= (*raw1 & 0x00000fc0L) >> 6;
        *cook = (*raw0 & 0x0003f000L) << 12;
        *cook |= (*raw0 & 0x0000003fL) << 16;
        *cook |= (*raw1 & 0x0003f000L) >> 4;
        *cook++ |= (*raw1 & 0x0000003fL);
    }
    usekey (dough);
    return;
}

void
cpkey (into)
     register unsigned long *into;
{
    register unsigned long *from,
    *endp;

    from = KnL, endp = &KnL[32];
    while (from < endp)
        *into++ = *from++;
    return;
}

void
usekey (from)
     register unsigned long *from;
{
    register unsigned long *to,
    *endp;

    to = KnL, endp = &KnL[32];
    while (to < endp)
        *to++ = *from++;
    return;
}

void
des (inblock, outblock)
     unsigned char *inblock,
     *outblock;
{
    unsigned long work[2];

    scrunch (inblock, work);
    desfunc (work, KnL);
    unscrun (work, outblock);
    return;
}

static void
scrunch (outof, into)
     register unsigned char *outof;
     register unsigned long *into;
{
    *into = (*outof++ & 0xffL) << 24;
    *into |= (*outof++ & 0xffL) << 16;
    *into |= (*outof++ & 0xffL) << 8;
    *into++ |= (*outof++ & 0xffL);
    *into = (*outof++ & 0xffL) << 24;
    *into |= (*outof++ & 0xffL) << 16;
    *into |= (*outof++ & 0xffL) << 8;
    *into |= (*outof & 0xffL);
    return;
}

static void
unscrun (outof, into)
     register unsigned long *outof;
     register unsigned char *into;
{
    *into++ = (*outof >> 24) & 0xffL;
    *into++ = (*outof >> 16) & 0xffL;
    *into++ = (*outof >> 8) & 0xffL;
    *into++ = *outof++ & 0xffL;
    *into++ = (*outof >> 24) & 0xffL;
    *into++ = (*outof >> 16) & 0xffL;
    *into++ = (*outof >> 8) & 0xffL;
    *into = *outof & 0xffL;
    return;
}

static unsigned long SP1[64] =
{
    0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
    0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
    0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
    0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
    0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
    0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
    0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
    0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
    0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
    0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
    0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
    0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
    0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
    0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L};

static unsigned long SP2[64] =
{
    0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
    0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
    0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
    0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
    0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
    0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
    0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
    0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
    0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
    0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
    0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
    0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
    0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
    0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
    0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
    0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L};

static unsigned long SP3[64] =
{
    0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
    0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
    0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
    0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
    0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
    0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
    0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
    0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
    0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
    0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
    0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
    0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
    0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
    0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
    0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
    0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L};

static unsigned long SP4[64] =
{
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
    0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
    0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
    0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
    0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
    0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
    0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
    0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
    0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L};

static unsigned long SP5[64] =
{
    0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
    0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
    0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
    0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
    0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
    0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
    0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
    0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
    0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
    0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
    0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
    0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
    0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
    0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
    0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
    0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L};

static unsigned long SP6[64] =
{
    0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
    0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
    0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
    0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
    0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
    0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
    0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
    0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
    0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
    0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
    0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
    0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
    0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
    0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L};

static unsigned long SP7[64] =
{
    0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
    0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
    0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
    0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
    0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
    0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
    0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
    0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
    0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
    0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
    0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
    0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
    0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
    0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
    0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
    0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L};

static unsigned long SP8[64] =
{
    0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
    0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
    0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
    0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
    0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
    0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
    0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
    0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
    0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
    0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
    0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
    0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
    0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
    0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
    0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
    0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L};

static void
desfunc (block, keys)
     register unsigned long *block,
     *keys;
{
    register unsigned long fval,
     work,
     right,
     leftt;
    register int round;

    leftt = block[0];
    right = block[1];
    work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
    right ^= work;
    leftt ^= (work << 4);
    work = ((leftt >> 16) ^ right) & 0x0000ffffL;
    right ^= work;
    leftt ^= (work << 16);
    work = ((right >> 2) ^ leftt) & 0x33333333L;
    leftt ^= work;
    right ^= (work << 2);
    work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
    leftt ^= work;
    right ^= (work << 8);
    right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL;

    for (round = 0; round < 8; round++)
    {
        work = (right << 28) | (right >> 4);
        work ^= *keys++;
        fval = SP7[work & 0x3fL];
        fval |= SP5[(work >> 8) & 0x3fL];
        fval |= SP3[(work >> 16) & 0x3fL];
        fval |= SP1[(work >> 24) & 0x3fL];
        work = right ^ *keys++;
        fval |= SP8[work & 0x3fL];
        fval |= SP6[(work >> 8) & 0x3fL];
        fval |= SP4[(work >> 16) & 0x3fL];
        fval |= SP2[(work >> 24) & 0x3fL];
        leftt ^= fval;
        work = (leftt << 28) | (leftt >> 4);
        work ^= *keys++;
        fval = SP7[work & 0x3fL];
        fval |= SP5[(work >> 8) & 0x3fL];
        fval |= SP3[(work >> 16) & 0x3fL];
        fval |= SP1[(work >> 24) & 0x3fL];
        work = leftt ^ *keys++;
        fval |= SP8[work & 0x3fL];
        fval |= SP6[(work >> 8) & 0x3fL];
        fval |= SP4[(work >> 16) & 0x3fL];
        fval |= SP2[(work >> 24) & 0x3fL];
        right ^= fval;
    }

    right = (right << 31) | (right >> 1);
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = (leftt << 31) | (leftt >> 1);
    work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
    right ^= work;
    leftt ^= (work << 8);
    work = ((leftt >> 2) ^ right) & 0x33333333L;
    right ^= work;
    leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffffL;
    leftt ^= work;
    right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
    leftt ^= work;
    right ^= (work << 4);
    *block++ = right;
    *block = leftt;
    return;
}

#ifdef D2_DES

void
des2key (hexkey, mode)                           /* stomps on Kn3 too */
     unsigned char *hexkey;                      /* unsigned char[16] */
     short mode;
{
    short revmod;

    revmod = (mode == EN0) ? DE1 : EN0;
    deskey (&hexkey[8], revmod);
    cpkey (KnR);
    deskey (hexkey, mode);
    cpkey (Kn3);                                 /* Kn3 = KnL */
    return;
}

void
Ddes (from, into)
     unsigned char *from,
     *into;                                      /* unsigned char[8] */
{
    unsigned long work[2];

    scrunch (from, work);
    desfunc (work, KnL);
    desfunc (work, KnR);
    desfunc (work, Kn3);
    unscrun (work, into);
    return;
}

void
D2des (from, into)
     unsigned char *from;                        /* unsigned char[16] */
     unsigned char *into;                        /* unsigned char[16] */
{
    unsigned long *right,
    *l1,
     swap;
    unsigned long leftt[2],
     bufR[2];

    right = bufR;
    l1 = &leftt[1];
    scrunch (from, leftt);
    scrunch (&from[8], right);
    desfunc (leftt, KnL);
    desfunc (right, KnL);
    swap = *l1;
    *l1 = *right;
    *right = swap;
    desfunc (leftt, KnR);
    desfunc (right, KnR);
    swap = *l1;
    *l1 = *right;
    *right = swap;
    desfunc (leftt, Kn3);
    desfunc (right, Kn3);
    unscrun (leftt, into);
    unscrun (right, &into[8]);
    return;
}

void
makekey (aptr, kptr)
     register char *aptr;                        /* NULL-terminated  */
     register unsigned char *kptr;               /* unsigned char[8] */
{
    register unsigned char *store;
    register int first,
     i;
    unsigned long savek[96];

    cpDkey (savek);
    des2key (Df_Key, EN0);
    for (i = 0; i < 8; i++)
        kptr[i] = Df_Key[i];
    first = 1;
    while ((*aptr != '\0') || first)
    {
        store = kptr;
        for (i = 0; i < 8 && (*aptr != '\0'); i++)
        {
            *store++ ^= *aptr & 0x7f;
            *aptr++ = '\0';
        }
        Ddes (kptr, kptr);
        first = 0;
    }
    useDkey (savek);
    return;
}

void
make2key (aptr, kptr)
     register char *aptr;                        /* NULL-terminated   */
     register unsigned char *kptr;               /* unsigned char[16] */
{
    register unsigned char *store;
    register int first,
     i;
    unsigned long savek[96];

    cpDkey (savek);
    des2key (Df_Key, EN0);
    for (i = 0; i < 16; i++)
        kptr[i] = Df_Key[i];
    first = 1;
    while ((*aptr != '\0') || first)
    {
        store = kptr;
        for (i = 0; i < 16 && (*aptr != '\0'); i++)
        {
            *store++ ^= *aptr & 0x7f;
            *aptr++ = '\0';
        }
        D2des (kptr, kptr);
        first = 0;
    }
    useDkey (savek);
    return;
}

#ifndef D3_DES                                   /* D2_DES only */
#ifdef  D2_DES                                   /* iff D2_DES! */

void
cp2key (into)
     register unsigned long *into;               /* unsigned long[64] */
{
    register unsigned long *from,
    *endp;

    cpkey (into);
    into = &into[32];
    from = KnR, endp = &KnR[32];
    while (from < endp)
        *into++ = *from++;
    return;
}

void
use2key (from)                                   /* stomps on Kn3 too */
     register unsigned long *from;               /* unsigned long[64] */
{
    register unsigned long *to,
    *endp;

    usekey (from);
    from = &from[32];
    to = KnR, endp = &KnR[32];
    while (to < endp)
        *to++ = *from++;
    cpkey (Kn3);                                 /* Kn3 = KnL */
    return;
}

#endif /* iff D2_DES */
#else /* D3_DES too */

static void D3des (unsigned char *, unsigned char *);

void
des3key (hexkey, mode)
     unsigned char *hexkey;                      /* unsigned char[24] */
     short mode;
{
    unsigned char *first,
    *third;
    short revmod;

    if (mode == EN0)
    {
        revmod = DE1;
        first = hexkey;
        third = &hexkey[16];
    }
    else
    {
        revmod = EN0;
        first = &hexkey[16];
        third = hexkey;
    }
    deskey (&hexkey[8], revmod);
    cpkey (KnR);
    deskey (third, mode);
    cpkey (Kn3);
    deskey (first, mode);
    return;
}

void
cp3key (into)
     register unsigned long *into;               /* unsigned long[96] */
{
    register unsigned long *from,
    *endp;

    cpkey (into);
    into = &into[32];
    from = KnR, endp = &KnR[32];
    while (from < endp)
        *into++ = *from++;
    from = Kn3, endp = &Kn3[32];
    while (from < endp)
        *into++ = *from++;
    return;
}

void
use3key (from)
     register unsigned long *from;               /* unsigned long[96] */
{
    register unsigned long *to,
    *endp;

    usekey (from);
    from = &from[32];
    to = KnR, endp = &KnR[32];
    while (to < endp)
        *to++ = *from++;
    to = Kn3, endp = &Kn3[32];
    while (to < endp)
        *to++ = *from++;
    return;
}

static void
D3des (from, into)                               /* amateur theatrics */
     unsigned char *from;                        /* unsigned char[24] */
     unsigned char *into;                        /* unsigned char[24] */
{
    unsigned long swap,
     leftt[2],
     middl[2],
     right[2];

    scrunch (from, leftt);
    scrunch (&from[8], middl);
    scrunch (&from[16], right);
    desfunc (leftt, KnL);
    desfunc (middl, KnL);
    desfunc (right, KnL);
    swap = leftt[1];
    leftt[1] = middl[0];
    middl[0] = swap;
    swap = middl[1];
    middl[1] = right[0];
    right[0] = swap;
    desfunc (leftt, KnR);
    desfunc (middl, KnR);
    desfunc (right, KnR);
    swap = leftt[1];
    leftt[1] = middl[0];
    middl[0] = swap;
    swap = middl[1];
    middl[1] = right[0];
    right[0] = swap;
    desfunc (leftt, Kn3);
    desfunc (middl, Kn3);
    desfunc (right, Kn3);
    unscrun (leftt, into);
    unscrun (middl, &into[8]);
    unscrun (right, &into[16]);
    return;
}

void
make3key (aptr, kptr)
     register char *aptr;                        /* NULL-terminated   */
     register unsigned char *kptr;               /* unsigned char[24] */
{
    register unsigned char *store;
    register int first,
     i;
    unsigned long savek[96];

    cp3key (savek);
    des3key (Df_Key, EN0);
    for (i = 0; i < 24; i++)
        kptr[i] = Df_Key[i];
    first = 1;
    while ((*aptr != '\0') || first)
    {
        store = kptr;
        for (i = 0; i < 24 && (*aptr != '\0'); i++)
        {
            *store++ ^= *aptr & 0x7f;
            *aptr++ = '\0';
        }
        D3des (kptr, kptr);
        first = 0;
    }
    use3key (savek);
    return;
}

#endif /* D3_DES */
#endif /* D2_DES */

/* Validation sets:
 *
 * Single-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef
 * Plain  : 0123 4567 89ab cde7
 * Cipher : c957 4425 6a5e d31d
 *
 * Double-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef fedc ba98 7654 3210
 * Plain  : 0123 4567 89ab cde7
 * Cipher : 7f1d 0a77 826b 8aff
 *
 * Double-length key, double-length plaintext -
 * Key    : 0123 4567 89ab cdef fedc ba98 7654 3210
 * Plain  : 0123 4567 89ab cdef 0123 4567 89ab cdff
 * Cipher : 27a0 8440 406a df60 278f 47cf 42d6 15d7
 *
 * Triple-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef fedc ba98 7654 3210 89ab cdef 0123 4567
 * Plain  : 0123 4567 89ab cde7
 * Cipher : de0b 7c06 ae5e 0ed5
 *
 * Triple-length key, double-length plaintext -
 * Key    : 0123 4567 89ab cdef fedc ba98 7654 3210 89ab cdef 0123 4567
 * Plain  : 0123 4567 89ab cdef 0123 4567 89ab cdff
 * Cipher : ad0d 1b30 ac17 cf07 0ed1 1c63 81e4 4de5
 *
 * original source: d3des V5.0a rwo 9208.07 18:44 Graven Imagery
 **********************************************************************/
