/* idea128c.c */
/* IDEA cipher: 128 bit key, 64 bit block in CBC mode */
/* CBF functions are implemented. */
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F IDEA_C.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include "crypt.h"
#include "hex.h"
#include "idea.h"
#include "nhash.h"

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file.

  In this case, the name of the EXE file is IDEA_C.EXE because
  the module IDEA.C contains the main cipher.
*/

static int key_defined = 0;                      /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static char key_string[257];
static char actual_key[16];                      /* base key */
static struct IdeaCfbContext cfb;                /* actual cfb */
 
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
    "      The program uses the IDEA cipher (International Data",
    "      Encryption Algorithm) formerly known as IPES in CBC mode.",
    "      A 128 bit key is used to encrypt a 64 bit block.",
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
    "      At most 256 characters will be used in the phrase.",
    "      If the string evaluates to exactly 16 hex bytes such as",
    "      \"F0AB 457E 006C E4AA 98B3 3A47 BCB5 C222\", but with",
    "      all spaces ignored, then that exact 128 bit key is used.",
    "      Otherwise, the ASCII characters are hashed to form a",
    "      128 bit key.  A zero key will produce a warning message.",
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
        key_string[i] = (char) (i & 0xff);

    for (i=0; i<16; i++)
        actual_key[i] = 0;

    ideaCfbDestroy( &cfb );

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
            if (key_defined)                     /* if we have a key, recalculate */
                process_key (key_string, actual_key);
        }
    }

    if (selection == DECRYPTION_SELECT)
    {
        if (encrypt_or_decrypt == ENCRYPTION_SELECT)
        {
            encrypt_or_decrypt = DECRYPTION_SELECT;
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
                ideaCfbEncrypt(&cfb, buffer, buffer, 8);
            else
            {
                ideaCfbEncrypt(&cfb, cbc, seed, 8);
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
                ideaCfbDecrypt(&cfb, buffer, buffer, 8);
            else
            {
                ideaCfbEncrypt(&cfb, fcbc, seed, 8);
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
            for (i = 0; i < 8; i++)
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
    int block_count;
    int shift = 1;
    int value = 0;
    int hex_count = 0;
    int nonhex_count = 0;
    int white_count = 0;

    char init[16] = 
    {  0xa1, 0x1f, 0x9d, 0x15, 0x3e, 0xdc, 0xeb, 0x85, 
       0xd0, 0x18, 0xc4, 0xbf, 0xb6, 0xf7, 0xa4, 0x9a
    };

    for (i=0; i<257; i++)
        string[i] = '\0';

    /* check for a hex number */
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

    if (hex_count == 32 && nonhex_count == 0)
    {                                            /* convert hex number */
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
        }
    }
    else if (!string[0]) 
    {                                            /* default key for no key phrase */
        for (i=0; i<16; i++)
            key[i] = init[i];
    }
    else
    {                                            /* process ASCII string */
        block_count = ( (strlen( string ) - 1 ) / 16 ) + 1;
        if (block_count > 16)
            block_count = 16;
        hash128 (block_count, string, init, key);
    }

    /* warn of weak keys */
    value = 0;
    for (j = 0; j < 16; j++)
        if (!key[j])
            value++;
    if (value == 16)
        fprintf (stderr, "A zero key has been detected.\n");

    /* clear local copy of string */
    for (i=0; i<256; i++)
        string[i] = '\0';

    /* select the key for use */
    ideaCfbInit( &cfb, key );
}
