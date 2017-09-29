/* tinyRSA.c */
/* RSA cipher: tiny version with 4-5 digit keys and cipher block chaining */
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* RSA cipher under U.S. patent 4405829 will expire September 20, 2000 */

/* tinyRSA should be considered only an educational tool because the */
/* small number of digits used in the key make decryption trivial. */
/* Use of this program is not in violation of U.S. patent 4405829 */
/* because it does not perform public key cryptography. */

/* Program TINYKEY should be used to generate public and private keys. */
/* Program TINYSOLV can generate private keys from public keys. */

/* If a version of TINYSOLV could be written for 200 digit keys, */
/* no current version of RSA would be secure. */

/* Theory of RSA:

   Choose two really large prime numbers p and q.
   (This program uses really small prime numbers p and q.)
   Then, p * q = n, where modulus n should have 150-200 digits.
   Select a random number e subject to the condition that
   e and (p-1)(q-1) are relatively prime, or gcd(e,(p-1)(q-1)) = 1.
   Finally, solve for d where e * d = 1 mod((p-1)(q-1)).
   We have e and n as public keys, d and n as private keys.
   The above procedure is done by key selection software.

   To encrypt message block x, calculate y = x^e mod(n).
   Tell everybody -- even your brother -- the values e and n.
   They can use the above formula to send you encrypted messages.
   To decrypt message block y, calculate x = y^d mod(n).
   Don't tell anybody the value of d.  As long as n is over
   120 digits, state of the art can not get d from e and n.
   The message blocks should have a length just short of the
   length of n.
*/

/* under MSDOS, NMAKE /F TINYRSA.MAK all clean */

/* Note:
   Encrypted files double in size.  This is a side effect of the
   way that tinyRSA is implemented.  With a little bit packing,
   the size of the encrypted files could be made smaller.  But,
   this is such an insecure implementation that you shouldn't
   be using it for anything serious anyway.
*/

#include <stdio.h>
#include <stdlib.h>
#include "crypt.h"

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file. 
*/

static int key_defined = 0;                      /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static char key_string[257];
static unsigned int key_1;
static unsigned int key_2;

int process_key ( char * );
long modexp_l ( long, long, long );

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[] =
{
    "CIPHER",
    "      The program uses the patented RSA cipher with 4-5 digit keys.",
    "      16 bit keys are is used to encrypt an 8 bit block with CBC.",
    "      For decryption, the 16 bit keys decrypt a 16 bit block to 8 bits.",
    "      Cipher block chaining uses zero based vector initialization.",
    "      Integer (16 bit or 4-5 digit) keys are used in this version.",
    "      The RSA cipher needs about 150 digits to be really secure.",
    "      This version is completely insecure and even includes a utility",
    "      to generate the private key from the public key.  However, the",
    "      program may be educational for learning about the cipher.",
    "",
    "      Use the -d option for decryption.",
    "",
    "KEY",
    "      The key consists of two decimal numbers in the range 2-65535.",
    "      The keys must be generated using the program TINYKEY.  Use the",
    "      public key pair with the -e option for encrytion and the private",
    "      key pair with the -d option for decryption.",
    "",
    "      On the command line with the -k option, enclose the two",
    "      decimal numbers in quotes.",
    "",
    "      If a key file exists, only the first line is read, and",
    "      it is used as the key pair.  Quotes are not needed.",
    "",
    "      If there is no key pair, you will be prompted for one.",
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
                    key_defined = process_key (key_string);
                    break;
                }
            }
            else if (i == 255)
            {
                *++s = '\0';
                key_defined = process_key (key_string);
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
                    key_defined = process_key (key_string);
                    break;
                }
                else if (i == 255)
                {
                    *++s = '\0';
                    key_defined = process_key (key_string);
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
            key_defined = process_key (key_string);
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
    
    key_1 = 0;
    key_2 = 0;

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
        encrypt_or_decrypt = ENCRYPTION_SELECT;

    if (selection == DECRYPTION_SELECT)
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
crypt_file (char *source, char *dest)
{
    int cbc;
    int fcbc;
    int count;
    int buffer;
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

    cbc = fcbc = buffer = 0;                       /* zero initialization vector */

    if (encrypt_or_decrypt == ENCRYPTION_SELECT)
        count = 1;
    else
        count = 2;

    while (count = fread ((char *) &buffer, sizeof (char), count, infile))
    {
        if (encrypt_or_decrypt == ENCRYPTION_SELECT)        
        {
            buffer ^= ((cbc & 0xff) & (cbc << 8)) ;
            buffer = (int) modexp_l((long) buffer, (long) key_1, (long) key_2);
            cbc = buffer;
        }
        else
        {
            cbc = buffer;
            buffer = (int) modexp_l((long) buffer, (long) key_1, (long) key_2);
            buffer ^= ((fcbc & 0xff) & (fcbc << 8));
            fcbc = cbc;
        }

        /* encrypt 1 byte into 2 bytes; decrypt 2 bytes to 1 byte */
        if ((3 - count) != fwrite ((char *) &buffer, sizeof (char), 3 - count, outfile))
        {
            fprintf (stderr, "Could not write to %s\n", source);
            fclose (infile);
            fclose (outfile);
            return 1;
        }
        else
            buffer = 0;
    }

    fclose (infile);
    fclose (outfile);
    return 0;
}

int
process_key(char *p)
{
    unsigned int i;
    char *s;

    s = p;

    /* skip non-digits */
    while (!isdigit(*s))
        if (*s != '\0')
            s++;
        else
            return 0;

    /* get first number */
    key_1 = 0;
    while (isdigit(*s))
        key_1 = (key_1 * 10) + (*s++ - '0');

    /* skip non-digits */
    while (!isdigit(*s))
        if (*s != '\0')
            s++;
        else
            return 0;

    /* get second number */
    key_2 = 0;
    while (isdigit(*s))
        key_2 = (key_2 * 10) + (*s++ - '0');
    
    /* force key_1 less than key_2 (n larger than e or d) */
    if (key_2 < key_1)
    {
        i = key_1;
        key_1 = key_2;
        key_2 = i;
    }

    /* error if either is zero */
    return key_1;
}

long
modexp_l(long a, long x, long n)
{
    long r = 1;

    while (x > 0)
    {
        if (x & 1)           /* is x odd? */
            r = (r * a) % n;
        a = (a*a) % n;
        x /= 2;
    }
    return r;
}

