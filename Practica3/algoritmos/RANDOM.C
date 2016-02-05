/* random.c */
/* XOR of input file with random numbers generated from a seed key string */
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F RANDOM.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include "crypt.h"
#include "rnd.h"

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file.
*/

static int key_defined = 0;       /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static char key_string[257];

/* implementation specific defines */

void hash128 (int, unsigned char *, unsigned char *, unsigned char *);
long hash_string( char * );

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[]=
{
  "CIPHER",
  "      The XOR cipher performs an EXCLUSIVE OR operation",
  "      with the output of a random number generator that is",
  "      seeded with a hashed key phrase.",
  "",
  "KEY",
  "      The key is an ASCII string.  If you use more than one",
  "      word in the phrase and give the key with the -k option",
  "      on the command line, place the phrase within quotes.",
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

    for (i=0; i<257; i++)                   /* initialize key string */
        key_string[i] = '\0';

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
                    initial_seed = hash_string( key_string );
                    key_defined = 1;
                    break;
                }
            }
            else if (i == 255)
            {
                *++s = '\0';
                initial_seed = hash_string( key_string );
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
                        initial_seed = hash_string( key_string );
                        key_defined = 1;
                        break;
                    }
                }
                else if (i == 255)
                {
                    *++s = '\0';
                    initial_seed = hash_string( key_string );
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
            initial_seed = hash_string( key_string );
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
    rnd_seed = 0;
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
    int c;
    unsigned long k;
    FILE *infile;
    FILE *outfile;

    while (!key_defined)
        crypt_key( KEY_IMMEDIATE, "?" );

    set_rnd_seed( initial_seed );

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

    while ((c = fgetc(infile)) != EOF)
    {
        k = (unsigned long) rnd();
        c ^= (int) ( 0xffff & k );
        if (fputc(c, outfile) == EOF)
        {
            fprintf(stderr, "Could not write to output file %s\n", dest);
            fclose( infile );
            fclose( outfile );
            return 1;
        }
    }

    fclose( infile );
    fclose( outfile );
    return 0;
}

/* hash a string into a long int */

long
hash_string( char * s )
{
    long k;
    int block_count;
    
    unsigned char init[16] = 
    { 0x3d, 0x38, 0x73, 0xc2, 0xa2, 0x37, 0x1a, 0x0f,
      0xa7, 0xec, 0x87, 0x22, 0xc9, 0xb8, 0x57, 0xab
    } ;

    union
    {
        long k[4];
        unsigned char array[16];
    } output;

    if (!*s)
        block_count = 0;
    else
    {
        block_count = ( (strlen( s ) - 1 ) / 16 ) +1;
        if (block_count > 16)
            block_count = 16;
    }

    hash128 (block_count, s, init, output.array);
    
    k = ( output.k[0] ^ output.k[1] ^ output.k[2] ^ output.k[3] );
    return k;
}
