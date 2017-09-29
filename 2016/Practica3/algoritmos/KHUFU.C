/* khufu.c */
/* Encrypt input file with the KHUFU cipher */ 
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F KHUFU.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include "crypt.h"
#include "rnd.h"

#ifndef uint32
typedef unsigned long uint32;
typedef unsigned char ubyte;
#endif

#ifndef bcopy
#define bcopy(src, dst, n)   memcpy ((dst), (src), (n))
#endif

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file.
*/

static int key_defined = 0;       /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static char key_string[257];

/* implementation specific defines */

#define	ENOUGH	16
#define	OCTETS	((ENOUGH+7)/8)

uint32 SBoxes[OCTETS][256];
uint32 AuxKeys[4];

void hash128 (int, unsigned char *, unsigned char *, unsigned char *);
long hash_string( char * );
void khufu( uint32 * );
void khufuinv( uint32 * );
void hashfilename( char *, char * );
void initialize_SBoxes( void );

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[]=
{
  "CIPHER",
  "      The KHUFU cipher uses a 64 bit block cipher.",
  "      The 256 entry S-boxes are generated from a hashed",
  "      key phrase.  Sixteen rounds are used.  This is a",
  "      variation of the Zachariassen implementation.  S-boxes",
  "      are not modified between rounds in this version.",
  "      To increase security, the simple file name of the",
  "      encrypted file is used as part of the key. The source",
  "      file name for encryption and destination name for",
  "      decryption should be the same.  Use -d for decryption.",
  "      Because input is processed in blocks of 8 bytes, files",
  "      not a multiple of 8 may increase in size with spaces",
  "      appended to the end.",
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
    int j;

    for (i=0; i<257; i++)
        key_string[i] = '\0';
    initial_seed = 0;
    rnd_seed = 0;
    for (i=0; i<256; i++)
        for (j=0; j<OCTETS; j++)
            SBoxes[j][i] = 0L;
    for (i=0; i<4; i++)
        AuxKeys[i] = 0L;
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
    char buffer[8];
    int count = 8;                               /* block size */
    int i;
    unsigned long k;
    FILE *infile;
    FILE *outfile;

    while (!key_defined)
        crypt_key( KEY_IMMEDIATE, "?" );

    initialize_SBoxes();

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

    /* Set AuxKeys from hashed file name.  This makes the encryption
       different for each file that has a different simple name. */

    if (encrypt_or_decrypt == ENCRYPTION_SELECT) 
        hashfilename(source, (char *) AuxKeys);      /* use source name */
    else                                         
        hashfilename(dest, (char *) AuxKeys);        /* use destination name */

    for (i = 0; i < count; i++)
        buffer[i] = (char) 0x20;                 /* text files padded with spaces */

    while (fread (buffer, sizeof (char), count, infile))
    {
        if (encrypt_or_decrypt == ENCRYPTION_SELECT)
            khufu((uint32 *) buffer);
        else
            khufuinv((uint32 *) buffer);
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

    fclose( infile );
    fclose( outfile );
    return 0;
}

/* hash_string: hash a string into a long int 
   
   The string can be up to 256 characters.  Zero characters will
   return the hashed init string.  If the string is not a multiple
   of 16 characters, pad the string with zeroes until it is a multiple
   of 16 including the zeroes.  Otherwise, the hash will not give
   the same result for the same input string when random bytes
   fill up the array to a multiple of 16 bytes long.
*/

long
hash_string( char * s )
{
    long k;
    int block_count;
    
    unsigned char init[16] = 
    {  0x7e, 0x7e, 0x72, 0x59, 0x73, 0xea, 0x5e, 0x2c,
       0xf8, 0x42, 0xa9, 0xe7, 0x31, 0x55, 0x8f, 0xf4
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

/* hashfilename:

   The filename can be of any format, but it must be guaranteed to
   exist and be findable.  In this implementation, this routine is 
   not called until there is a successful open of the file.  We will
   use MSC functions to scan the file name and obtain the simple
   file name.  It will be forced to a length of 8 with padding
   of spaces if necessary.  The name will then be doubled up to
   get 16 bytes, hashed, and saved in the destination, which must
   hold 16 characters, or 4 longs. 
*/

void
hashfilename( char * filename, char * destination )
{

    unsigned char init[16] = 
    {   0x7d, 0xe1, 0x27, 0xdc, 0x78, 0x79, 0x5f, 0xe4, 
        0xda, 0xb9, 0x96, 0x82, 0x50, 0x5a, 0xe7, 0x81
    } ;
    unsigned char name[16];
    char sDrive[_MAX_DRIVE];
    char sDir[_MAX_DIR];
    char sFname[_MAX_FNAME];
    char sExt[_MAX_EXT];
    int i;

    _splitpath( filename, sDrive, sDir, sFname, sExt );
    for (i=0; i<16; i++)
        name[i] = ' ';
    for (i=0; i<8; i++)
        if (sFname[i] == '\0')
            break;
        else
            name[i] = name[i+8] = toupper(sFname[i]);
    hash128 (1, name, init, destination);
    return;
}

/*
 * Copyright 1989 by Rayan Zachariassen.  Use and distribute as you see fit
 * as long as you send code/cipher improvements or interesting results
 * back to me.  
 */

void
khufu(uint32 * datap)
{
	register uint32 L, R;
	register int octet;

	L = *datap++ ^ AuxKeys[0];
	R = *datap ^ AuxKeys[1];

	for (octet = OCTETS-1; octet >= 0; --octet) {
#define	ROUND(LEFT,RIGHT,ROTN) \
		RIGHT ^= SBoxes[octet][LEFT & 0xff]; \
		LEFT = (LEFT)>>(ROTN) | (LEFT)<<(32-ROTN);

		ROUND(L,R,16);
		ROUND(R,L,16);
		ROUND(L,R,8);
		ROUND(R,L,8);
		ROUND(L,R,16);
		ROUND(R,L,16);
		ROUND(L,R,24);
		ROUND(R,L,24);
	}

	*datap = R ^ AuxKeys[3];
	*--datap = L ^ AuxKeys[2];
}

void
khufuinv(uint32 * datap)
{
	register uint32 L, R;
	register int octet;

	L = *datap++ ^ AuxKeys[2];
	R = *datap ^ AuxKeys[3];

	for (octet = 0; octet < OCTETS; ++octet) {
#define	ROUNDINV(LEFT,RIGHT,ROTN) \
		LEFT = (LEFT)<<(ROTN) | (LEFT)>>(32-ROTN); \
		RIGHT ^= SBoxes[octet][LEFT & 0xff]; \

		ROUNDINV(R,L,24);
		ROUNDINV(L,R,24);
		ROUNDINV(R,L,16);
		ROUNDINV(L,R,16);
		ROUNDINV(R,L,8);
		ROUNDINV(L,R,8);
		ROUNDINV(R,L,16);
		ROUNDINV(L,R,16);
	}

	*datap = R ^ AuxKeys[1];
	*--datap = L ^ AuxKeys[0];
}

void
initialize_SBoxes( void )
{
    /* First fill the S-boxes with pseudo random numbers with a seed
       from the hashed key phrase.  Then hash each block of the S-boxes. 
       This is not the recommended initialization. */

    unsigned char init[16] = 
    {   0x5e, 0xc1, 0xe1, 0x4e, 0xc7, 0x3c, 0x73, 0x07, 
        0xcb, 0xe7, 0x74, 0x1b, 0x27, 0x2d, 0x04, 0x49
    } ;
    char * s;
    long * l;
    int c;

    l = (long *) SBoxes;
    set_rnd_seed( initial_seed );
    for (c=0; c<sizeof(SBoxes); c+=sizeof(long))
        *l++ = rnd();

    s = (char *) SBoxes;
    for (c=0; c<sizeof(SBoxes); c+=16)
        hash128 (1, (s+c), init, (s+c));
}

