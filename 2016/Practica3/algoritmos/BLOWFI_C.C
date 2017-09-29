/* blowfi_c.c */
/* blowfish cipher: 64 bit key, 64 bit block by Bruce Schneier */
/* This version implements cipher block chaining */
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F BLOWFI_C.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "crypt.h"
#include "hex.h"
#include "blowfish.h"

#ifdef big_endian
#include <Types.h>
#endif

unsigned int crc (unsigned char , unsigned int );

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file.
*/

static int key_defined = 0;                      /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static char key_string[257];

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[] =
{
    "CIPHER",
    "      The program uses the BLOWFISH cipher by Bruce Schneier.",
    "      A 64 bit key is used to encrypt a 64 bit block in CBC mode.",
    "      Cipher block chaining uses vector initialization preset to the",
    "      simple 8 character file name.  The initialization is given by",
    "      the source file name on encryption, and destination file name",
    "      on decryption.  The simple file name of the decrypted file must",
    "      be the same as the simple file name of the original file.",
    "      Files with less than 8 bytes are not secure.",
    "",
    "      Use the -d option for decryption.",
    "",
    "KEY",
    "      The key is an ASCII string.  If you use more than one",
    "      word in the phrase and give the key with the -k option",
    "      on the command line, place the phrase within quotes.",
    "      At most 72 characters will be used in the phrase.",
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
                    key_defined = !InitializeBlowfish(key_string, strlen(key_string));
                    break;
                }
            }
            else if (i == 255)
            {
                *++s = '\0';
                key_defined = !InitializeBlowfish(key_string, strlen(key_string));
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
                    key_defined = !InitializeBlowfish(key_string, strlen(key_string));
                    break;
                }
                else if (i == 255)
                {
                    *++s = '\0';
                    key_defined = !InitializeBlowfish(key_string, strlen(key_string));
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
            key_defined = !InitializeBlowfish(key_string, strlen(key_string));
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
        encrypt_or_decrypt = ENCRYPTION_SELECT;
    }

    if (selection == DECRYPTION_SELECT)
    {
        encrypt_or_decrypt = DECRYPTION_SELECT;
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
                Blowfish_encipher((unsigned long *) buffer,(unsigned long *) &buffer[4]);
            else
            {
                for (i=0; i<8; i++)
                    seed[i] = cbc[i];
                Blowfish_encipher((unsigned long *) seed,(unsigned long *) &seed[4]);
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
                Blowfish_decipher((unsigned long *) buffer,(unsigned long *) &buffer[4]);
            else
            {
                for (i=0; i<8; i++)
                    seed[i] = fcbc[i];
                Blowfish_encipher((unsigned long *) seed,(unsigned long *) &seed[4]);
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

/* blowfish.c written by Bruce Schneier */
/* Checksum of subkey file added by Willis E. Howard, III */

#define N               16
#define noErr            0
#define DATAERROR         -1
#define KEYBYTES         8
#define subkeyfilename   "Blowfish.dat"
#define FILECHECKSUM     38491

unsigned long P[N + 2];
unsigned long S[4][256];
FILE *SubkeyFile;

short 
opensubkeyfile (void)                            /* read only */
{
    short error;
    unsigned int i;
    unsigned int total = 0;

    if ((SubkeyFile = fopen (subkeyfilename, "rb")) == NULL)
    {
        printf("Can not open data file %s\n", subkeyfilename);
        return DATAERROR;
    }

    while ((i = fgetc(SubkeyFile)) != EOF)
       total = crc ( (char) i, total );
    total = crc ( 0, total );
    total = crc ( 0, total );

    if (total != FILECHECKSUM)
    {
        printf("Bad checksum in data file %s\n", subkeyfilename);
        printf("Checksum was %u, but should be %u\n", total, FILECHECKSUM);
        fclose(SubkeyFile);
        return DATAERROR;
    }
    fclose(SubkeyFile);

    if ((SubkeyFile = fopen (subkeyfilename, "rb")) == NULL)
    {
        return DATAERROR;
    }

    return noErr;
}

unsigned long 
F (unsigned long x)
{
    unsigned short a;
    unsigned short b;
    unsigned short c;
    unsigned short d;
    unsigned long y;

    d = x & 0x00FF;
    x >>= 8;
    c = x & 0x00FF;
    x >>= 8;
    b = x & 0x00FF;
    x >>= 8;
    a = x & 0x00FF;
    //y = ((S[0][a] + S[1][b]) ^ S[2][c]) + S[3][d];
    y = S[0][a] + S[1][b];
    y = y ^ S[2][c];
    y = y + S[3][d];

    return y;
}

void 
Blowfish_encipher (unsigned long *xl, unsigned long *xr)
{
    unsigned long Xl;
    unsigned long Xr;
    unsigned long temp;
    short i;

    Xl = *xl;
    Xr = *xr;

    for (i = 0; i < N; ++i)
    {
        Xl = Xl ^ P[i];
        Xr = F (Xl) ^ Xr;

        temp = Xl;
        Xl = Xr;
        Xr = temp;
    }

    temp = Xl;
    Xl = Xr;
    Xr = temp;

    Xr = Xr ^ P[N];
    Xl = Xl ^ P[N + 1];

    *xl = Xl;
    *xr = Xr;
}

void 
Blowfish_decipher (unsigned long *xl, unsigned long *xr)
{
    unsigned long Xl;
    unsigned long Xr;
    unsigned long temp;
    short i;

    Xl = *xl;
    Xr = *xr;

    for (i = N + 1; i > 1; --i)
    {
        Xl = Xl ^ P[i];
        Xr = F (Xl) ^ Xr;

        /* Exchange Xl and Xr */
        temp = Xl;
        Xl = Xr;
        Xr = temp;
    }

    /* Exchange Xl and Xr */
    temp = Xl;
    Xl = Xr;
    Xr = temp;

    Xr = Xr ^ P[1];
    Xl = Xl ^ P[0];

    *xl = Xl;
    *xr = Xr;
}

short 
InitializeBlowfish (char key[], short keybytes)
{
    short i;
    short j;
    short k;
    short error;
    short numread;
    unsigned long data;
    unsigned long datal;
    unsigned long datar;

    /* First, open the file containing the array initialization data */
    error = opensubkeyfile ();
    if (error == noErr)
    {
        for (i = 0; i < N + 2; ++i)
        {
            numread = fread (&data, 4, 1, SubkeyFile);
#ifdef little_endian                             /* Eg: Intel   We want to process things in byte   */
                                                 /*   order, not as rearranged in a longword          */
            data = ((data & 0xFF000000) >> 24) |
                ((data & 0x00FF0000) >> 8) |
                ((data & 0x0000FF00) << 8) |
                ((data & 0x000000FF) << 24);
#endif

            if (numread != 1)
            {
                return DATAERROR;
            }
            else
            {
                P[i] = data;
            }
        }

        for (i = 0; i < 4; ++i)
        {
            for (j = 0; j < 256; ++j)
            {
                numread = fread (&data, 4, 1, SubkeyFile);

#ifdef little_endian                             /* Eg: Intel   We want to process things in byte   */
                                                 /*   order, not as rearranged in a longword          */
                data = ((data & 0xFF000000) >> 24) |
                    ((data & 0x00FF0000) >> 8) |
                    ((data & 0x0000FF00) << 8) |
                    ((data & 0x000000FF) << 24);
#endif

                if (numread != 1)
                {
                    return DATAERROR;
                }
                else
                {
                    S[i][j] = data;
                }
            }
        }

        fclose (SubkeyFile);

        j = 0;
        for (i = 0; i < N + 2; ++i)
        {
            data = 0x00000000;
            for (k = 0; k < 4; ++k)
            {
                data = (data << 8) | key[j];
                j = j + 1;
                if (j >= keybytes)
                {
                    j = 0;
                }
            }
            P[i] = P[i] ^ data;
        }

        datal = 0x00000000;
        datar = 0x00000000;

        for (i = 0; i < N + 2; i += 2)
        {
            Blowfish_encipher (&datal, &datar);

            P[i] = datal;
            P[i + 1] = datar;
        }

        for (i = 0; i < 4; ++i)
        {
            for (j = 0; j < 256; j += 2)
            {

                Blowfish_encipher (&datal, &datar);

                S[i][j] = datal;
                S[i][j + 1] = datar;
            }
        }
    }
    else
    {
        printf ("Unable to open subkey initialization file : %d\n", error);
    }
    return error;
}

/* crc from PGP - update 16-bit CRC:  X^16 + X^12 + X^5 + 1 */

unsigned int
crc (unsigned char new, unsigned int value)
{
    unsigned int 
        shift, 
        flag, 
        data;

    data = ((unsigned int) new) & 0xff;
    for (shift = 0x80; shift; shift >>= 1)
    {
        flag = (value & 0x8000);
        value <<= 1;
        value |= ((shift & data) ? 1 : 0);
        if (flag)
            value ^= 0x1021;
    }
    return (value & 0xffff);
}

