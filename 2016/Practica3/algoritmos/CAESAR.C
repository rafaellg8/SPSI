/* caesar.c */
/* Shift 3 position Caesar cipher */
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F CAESAR.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include "crypt.h"

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file.
*/

static int encrypt_or_decrypt = ENCRYPTION_SELECT;

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[]=
{
  "CIPHER",
  "      The CAESAR cipher shifts letters 3 places to the right mod 26.",
  "      To decrypt the CAESAR cipher, use the -d option which will",
  "      shift letters 3 places to the left mod 26.",
  "",
  "      For example, the CAESAR cipher converts an A to a D, a B to",
  "      an E, and so forth.  Upon decryption, a D is converted to an A,",
  "      an E to a B, and so forth.  Only letters are affected.  Upper",
  "      and lower case are retained in this version.",
  "",
  "      This cipher is mostly for historical interest.  It is said",
  "      that Julius Caesar used it to send his secret messages.",
  "",
  "KEY",
  "      No key is used by this function.",
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
    if (key_type == KEY_FILE)               /* a file name has been given */
    {
        return 0;
    }
    else if (key_type == KEY_IMMEDIATE)     /* a key string has been given */
    {
        if (!strcmp( key_text, "?" ))     /* prompt for key */
        {
            printf("No key needed\n");
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

    This version can be easily changed to give a key for the
    index number.  By default, the number is now 3.
*/

int    
crypt_file( char *source, char *dest )
{
    int c;
    int index;
    FILE *infile;
    FILE *outfile;

    index = 3;

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

    if ( encrypt_or_decrypt == ENCRYPTION_SELECT )
    {
        while ((c = fgetc(infile)) != EOF)
        {
            if (isalpha(c))
            {
                if(toupper(c) <= 'Z' - index)
                     c += index;
                else
                     c -= (26 - index);
            }
            if (fputc(c, outfile) == EOF)
            {
                fprintf(stderr, "Could not write to output file %s\n", dest);
                fclose( infile );
                fclose( outfile );
                return 1;
            }
        }
    }
    else if ( encrypt_or_decrypt == DECRYPTION_SELECT )
    {
        while ((c = fgetc(infile)) != EOF)
        {
            if (isalpha(c))
            {
                if (toupper(c) >= 'A' + index)
                    c -= index;
                else
                    c += (26 - index);
            }
            if (fputc(c, outfile) == EOF)
            {
                fprintf(stderr, "Could not write to output file %s\n", dest);
                fclose( infile );
                fclose( outfile );
                return 1;
            }
        }
    }

    fclose( infile );
    fclose( outfile );
    return 0;
}

