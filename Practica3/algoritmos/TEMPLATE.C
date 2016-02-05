/* template.c */
/* Generic character cipher. */
/* Unmodified, the input file is copied to output file */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F GENERIC1.MAK all clean */

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
static char key_string[257];      /* The key string is stored here */

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[]=
{
  "CIPHER",
  "      This program is a template for a character cipher.",
  "      Unmodified, the input file is copied to the output file.",
  "",
  "KEY",
  "      The key is an ASCII string.  If you use more than one",
  "      word in the phrase and give the key with the -k option",
  "      on the command line, place the phrase within quotes.",
  "      At most 256 characters can be used in the phrase.",
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
    return cipher_doc;         /* return a pointer to the help strings */
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
    int c;
    FILE *infile;
    FILE *outfile;

    /* Make sure we have a key string */

    while (!key_defined)
        crypt_key( KEY_IMMEDIATE, "?" );

    /* Do any processing of the key string here */

    /* Open the input and output files */

    if ((infile = fopen( source, "rb" )) == NULL)
    {
        fprintf( stderr, "Can not open %s for read.\n", source);
        return 1;
    }

    if ((outfile = fopen( dest, "wb" )) == NULL)
    {
        fprintf( stderr, "Can not open %s for write.\n", dest);
        fclose( infile );
        return 1;
    }

    /* Process the input to the output */

    while ((c = fgetc(infile)) != EOF)
    {
        /* Put the character cipher here. */

        if (fputc(c, outfile) == EOF)
        {
            fprintf(stderr, "Could not write to output file %s\n", dest);
            fclose( infile );
            fclose( outfile );
            return 1;
        }
    }

    /* Close the files */

    fclose( infile );
    fclose( outfile );
    return 0;
}
