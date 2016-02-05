/* vigenere.c */
/* Classical Vigenere cipher */
/* Taken from B. Schneier's sample program in Applied Cryptography */
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F VIGENERE.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include "crypt.h"

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file.
*/

static int key_defined = 0;       /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static char key_string[257];

/* Special defines for this module only */

/* number of letters in the alphabet */
#define ALPHA_LEN 26

/* 
   A more true VIGENERE cipher maps everything to upper case.
   To achieve that, set SAVE_CASE to 0 and use an upper case
   only encryption/decryption key.  The origial cipher also
   jumbles spaces between words.  This version retains all word
   lengths and non-alphabetical characters, allowing a true
   reconstruction of the original text with the VIGENERE cipher. 
*/
#define SAVE_CASE (1)

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[]=
{
  "CIPHER",
  "      The VIGENERE cipher is a polyalphabetic substitution cipher.",
  "      One letter of the key is used to encrypt one letter of text.",
  "      As letters of the key are used up, the key is reused.  To",
  "      decrypt the encrypted text, use the -d option and the same key.",
  "      This version retains character case.",
  "",
  "      This cipher is mostly for historical interest.  It was used",
  "      during the American Civil War, and has recently been used in",
  "      WordPerfect encryption.",
  "",
  "KEY",
  "      The key is an ASCII string of alphabetic characters.",
  "      Using non-alphabetical key characters may corrupt the text.",
  "      At most 256 characters will be used in the phrase.",
  "",
  "      If a key file exists, only the first line is read, and",
  "      it is used as the key phrase.",
  "",
  "      If there is no key phrase, you will be prompted for one.",
  NULL
} ;

char **
crypt_help()
{
    return cipher_doc;          /* return a pointer to the help strings */
}

/*
   crypt_key:
   Get the key from the passed string (that may be a file name in some
   implementations) or from a key file name.  Return 0 on success but
   exit on error.  
*/

int
crypt_key ( int key_type, char *key_text )
{
    int i;
    char *s;
    FILE *fp;

    if (key_type == KEY_FILE)               /* a file name has been given */
    {
        if ((fp=fopen(key_text, "r")) == NULL)
        {
            key_defined = 0;
            return 0;
        }
        s = key_string;
        i = 0;
        for (;;)
        {
            *s = fgetc( fp );
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
                    key_defined = 1;
                    break;
                }
            }
            else if (i == 255)
            {
                *++s = '\0';
                key_defined= 1;
                break;
            }
            s++;
            i++;
        }
        fclose( fp );
        return 0;
    }
    else if (key_type == KEY_IMMEDIATE)     /* a key string has been given */
    {
        if (!strcmp( key_text, "?" ))       /* prompt for key */
        {
            printf("Key: ");                /* input key from stdin */
            s = key_string;
            i = 0;
            for (;;)
            {
                *s = fgetc( stdin );
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
                        key_defined = 1;
                        break;
                    }
                }
                else if (i == 255)
                {
                    *++s = '\0';
                    key_defined = 1;
                    break;
                }
                s++;
                i++;
            }
        }
        else                                /* copy string up to 256 characters */
        {
            strncpy( key_string, key_text, 256 );
            key_string[256] = '\0';
            key_defined = 1;
        }
        return 0;
    }
    fprintf( stderr, "Error getting key\n" );
    exit( 1 );
}

/*
   crypt_key_erase:
   If a local copy of the key has been made, erase it from memory.
   This increases security that the key can not be obtained from
   an examination of memory.
*/

void
crypt_key_erase()
{
    int i;

    for (i=0; i<257; i++)
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
crypt_select( int selection )
{
    if ( selection == ENCRYPTION_SELECT )
        encrypt_or_decrypt = ENCRYPTION_SELECT;
    if ( selection == DECRYPTION_SELECT )
        encrypt_or_decrypt = DECRYPTION_SELECT;
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
crypt_file( char *source, char *dest )
{
    char *s;
    char case_char;
    int c;
    FILE *infile;
    FILE *outfile;

    while (!key_defined)
        crypt_key( KEY_IMMEDIATE, "?" );

    if ((infile = fopen( source, "rb" )) == NULL)
    {
        fprintf( stderr, "Can not open %s for reading.\n", source);
        return 1;
    }

    if ((outfile = fopen( dest, "wb" )) == NULL)
    {
        fprintf( stderr, "Can not open %s for writing.\n", dest);
        fclose( infile );
        return 1;
    }

    s = key_string;
    while ( (c = fgetc( infile )) != EOF )
    {
        if ( !*s )
            s = key_string;

        if (isalpha(c))
        {
            if (SAVE_CASE)
                case_char = c;
            else
                case_char = *s;
            c = toupper(c) - 'A';
            if ( encrypt_or_decrypt == ENCRYPTION_SELECT )
                c = (c + (toupper(*s) - 'A')) % ALPHA_LEN;
            else
                c = (c + ALPHA_LEN - (toupper(*s) - 'A')) % ALPHA_LEN;
            c = c + (isupper(case_char) ? 'A' : 'a');
        }
        if ( fputc( c, outfile ) == EOF )
        {
            fprintf( stderr, "Could not write to output file %s\n", dest );
            fclose( infile );
            fclose( outfile );
            return 1;
        }
        s++;
    }

    fclose( infile );
    fclose( outfile );
    return 0;
}
