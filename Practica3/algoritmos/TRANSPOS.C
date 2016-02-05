/* transpos.c */
/* transposition of rows with columns of an input block */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F TRANSPOS.MAK all clean */

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

/* implementation specific defines */

int rows;
int columns;
int validate_key(char *);
int setblock( void );
int isqrt( unsigned int );
static struct transpose
{
    char data[16384];
    int max;
    int left;
    char *start;
    char *next;
    int count;
    int row;
    int column;
}   trans;

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[]=
{
  "CIPHER",
  "      The TRANSPOSITION cipher reads in a block of data,",
  "      exchanges rows and columns, and writes the block out.",
  "      This is repeated for all blocks in the input file.",
  "      Unless a square block is used, the -d option must be",
  "      used for decryption.",
  "",
  "KEY",
  "      The key is one or two numbers.  If you use more than one",
  "      number and give the key with the -k option on the command",
  "      line, place the phrase within quotes.  The first number is",
  "      the number of rows.  If a second number is given, it is the",
  "      number of columns.  Without a second number, the block will",
  "      have the number of rows and columns given by the first.  If",
  "      there is not enough data to fill the block, a smaller block",
  "      size is used.  The largest dimensions are 128 rows and 128",
  "      columns.  The smallest are 2 rows and 2 columns.  If data",
  "      does not completely fill a block, smaller sizes are used.",
  "",
  "      If a key file exists, only the first line is read, and",
  "      it is used as the key.  Use no quotes in the key file.",
  "",
  "      If there is no key, you will be prompted for one.",
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

    if (key_type == KEY_FILE)               /* see if a file name has been given */
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
                    key_defined = validate_key(key_string);
                    break;
                }
            }
            else if (i == 255)
            {
                *++s = '\0';
                key_defined = validate_key(key_string);
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
                        key_defined = validate_key(key_string);
                        break;
                    }
                }
                else if (i == 255)
                {
                    *++s = '\0';
                    key_defined = validate_key(key_string);
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
            key_defined = validate_key(key_string);
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
    rows = 0;
    columns = 0;
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
    int iRow;
    int iCol;
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

    if ( encrypt_or_decrypt == DECRYPTION_SELECT )
    {
        c = rows;
        rows = columns;
        columns = c;
    }

    trans.max = rows * columns;
    while (trans.left=fread (trans.data, sizeof (char), trans.max, infile))
    {
        trans.next = trans.data;
        while (setblock() != 0)
            for(iCol=0; iCol<trans.column; iCol++)
                for(iRow=0; iRow<trans.row ;iRow++)
                {
                    c = *((trans.start)+iCol+iRow*(trans.column));
                    if (fputc(c, outfile) == EOF)
                    {
                        fprintf(stderr, "Could not write to output file %s\n", dest);
                        fclose( infile );
                        fclose( outfile );
                        return 1;
                    }
                }
        if(trans.left)                            /* if less than 3 bytes, reverse */
            for(iCol=0; iCol<trans.left; iCol++)
            {
                c = *(trans.start + trans.left - 1 - iCol);
                if (fputc(c, outfile) == EOF)
                {
                    fprintf(stderr, "Could not write to output file %s\n", dest);
                    fclose( infile );
                    fclose( outfile );
                    return 1;
                }
            }
    }

    if ( encrypt_or_decrypt == DECRYPTION_SELECT )
    {
        c = rows;
        rows = columns;
        columns = c;
    }

    fclose( infile );
    fclose( outfile );
    return 0;
}

int
validate_key(char *s)
{
    int i;
    
    while ((*s == ' ') || (*s == '\"'))           /* get rid of spaces, quotes */
        s++;
    
    for (i=0; isdigit(*s); s++)                   /* get first number */
        i = (i * 10) + (int) ((*s) - '0');
    if (i == 0)                                   /* no number is no good */
        return 0;
    if (i < 3)                                    /* 2 is the smallest */
        i = 2;
    if (i > 128)                                  /* 128 is the largest */
        i = 128;
    rows = i;                                     /* set the row */

    while (*s == ' ')                             /* get rid of spaces */
        s++;

    for (i=0; isdigit(*s); s++)                   /* get second number */
        i = (i * 10) + (int) ((*s) - '0');
    if (i == 0)                                   /* no number is OK */
        i = rows;                                 /* set columns to rows */
    if (i < 3)                                    /* check for minimum */
        i = 2;
    if (i > 128)                                  /* check for maximum */
        i = 128;
    columns = i;                                  /* set the column */

    return 1;                                     /* good return code */
}

int
setblock( void )
{
    if (trans.left < 4)                           /* the real easy part */
    {
        trans.start = trans.next;
        return 0;
    }

    if (trans.left == rows*columns)               /* the fairly easy part */
    {
        trans.count = trans.left;
        trans.left = 0;
        trans.start = trans.next;
        trans.row = rows;
        trans.column = columns;
        return 1;
    }

    /* OK, we got here because there was not enough data to fill the
       rows * columns array.  For the rest of the data in the file
       we have to break it up into smaller parts. The tricky part. */

    trans.row = isqrt((unsigned) trans.left);      /* guaranteed minimum of 4 bytes */
    trans.column = trans.row;
    trans.start = trans.next;
    trans.count = trans.column*trans.row;
    trans.left -= trans.count;
    trans.next += trans.count;
    return 1;
}

/* compute the integer square root of an unsigned integer */

int
isqrt(unsigned int input)
{
    union { struct { unsigned int input;
                     unsigned int newbits;
                   } x;
            long whole;
          } shift;
    unsigned int bitcount;
    unsigned int remainder;
    unsigned int diff;
    int result;

    if (!input)         /* 0 is 0 */
         return 0;

    /* just a bit of setup */
    bitcount = diff = remainder = result = shift.x.newbits = 0;
    shift.x.input = input;
   
    /* Compute the square root the old fashioned way. 
       Good up to 16 bits in, 8 bits out.
       The remainder is truncated.  */

    do                                 /* first skip over those annoying zeroes */
    {
        bitcount++;
        shift.whole <<= 2;
    }   while (shift.x.newbits == 0);
    do                                 /* now just like you learned in school, but base 2 */
    {
        remainder = ((remainder - diff) << 2) + shift.x.newbits;
        diff = ((result << 2) + 1) > remainder ? 0 : (result << 2) + 1;
        result = (result * 2) + (diff ? 1 : 0);
        shift.x.newbits = 0;
        shift.whole <<= 2;
    }   while(bitcount++ < 8);

    return result;
}
