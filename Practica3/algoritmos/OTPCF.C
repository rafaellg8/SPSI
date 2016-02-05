/* otpcf.c */
/* XOR with a one time pad file having an offset to start of file. */
/* OTP stream is compressed to reduce redundancy. */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F OTPCF.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "tempfile.h"
#include "zblock.h"

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file.
*/

static int key_defined = 0;                      /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static char key_string[257];

/* module specific */

static FILE *otpfile;
static struct zipblock otpblock;
static struct zipblock ziptemp;
static char otp_name[80];
static long offset;
static int validate_string (char *);
static char key_file_name[80];
static long otp_compression_count;

void key_update (void);
long check_key (char *, long);
int compress_otp( void );
int compress_advance( long );

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[] =
{
    "CIPHER",
    "      This program performs an EXCLUSIVE OR operation between a file and",
    "      the contents of a compressed one time pad (OTP) file.  Failure",
    "      occurs if the compressed OTP file is shorter than the input file.",
    "      The cipher does not require the -d option.  After each file",
    "      is processed, a line is output with decryption information:",
    "      output file name, OTP name, OTP offset, and next offset.",
    "      It is very important to keep this information for decyrption.",
    "      If the key file exists, it will be updated.",
    "",
    "KEY",
    "      The key is an ASCII string, given as \"FILENAME.EXT OFFSET\"",
    "      where the filename identifies the file that you have selected",
    "      to use as a one time pad.  The offset is the offset from the",
    "      beginning of the one time pad file, starting at 0.  It may be",
    "      omitted, in which case the file is used from the start.  If",
    "      an offset is given, enclose the entire phrase within quotes.",
    "",
    "      If a key file exists, the first line is read, and it is scanned",
    "      for the file name and the optional offset.  If you also give a",
    "      filename but no offset for the key on the command line, the key",
    "      file will be searched for an offset.  If not found, 0 is used.",
    "      If you give a filename and offset on the command line for the key,",
    "      this overrides any information in the key file.  Do not use",
    "      quotes in the key file.  If the key file is read-only, it will",
    "      be completely ignored to prevent repeated use of the same pad.",
    "",
    "      If there is no key or key file, you will be prompted for a key.",
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
   implementations) or from a key file name.  Return 0 on success and
   non-zero on error.
*/

int
crypt_key (int key_type, char *key_text)
{
    int i;
    char *s;
    FILE *fp;

    if (key_defined)                             /* cleanup before next key */
    {
        fclose(otpfile);
        key_defined = 0;
        key_update ();
    }

    for (i = 0; i < 257; i++)                    /* initialize key string */
        key_string[i] = '\0';

    if (key_type == KEY_FILE)                    /* a file name has been given */
    {
        strcpy (key_file_name, key_text);
        if ((fp = fopen (key_text, "r+")) == NULL)
            return 0;
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
                    key_defined = validate_string (key_string);
                    break;
                }
            }
            else if (i == 255)
            {
                *++s = '\0';
                key_defined = validate_string (key_string);
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
                    if (i == 0)
                    {
                        key_defined = 0;
                        break;
                    }
                    else
                    {
                        key_defined = validate_string (key_string);
                        break;
                    }
                }
                else if (i == 255)
                {
                    *++s = '\0';
                    key_defined = validate_string (key_string);
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
            key_defined = validate_string (key_string);
        }
        return 0;
    }
    fprintf (stderr, "Error getting key\n");
    return 1;
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

    if (key_defined)                             /* cleanup before exit */
    {
        key_update ();
        key_defined = 0;
        fclose (otpfile);
    }

    for (i = 0; i < 257; i++)
        key_string[i] = '\0';
    offset = 0;
    for (i = 0; i < 80; i++)
        otp_name[i] = '\0';
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
    int c;
    int o;
    FILE *infile;
    FILE *outfile;

    while (!key_defined)
        crypt_key (KEY_IMMEDIATE, "?");

    if ((infile = fopen (source, "rb")) == NULL)
    {
        fprintf (stderr, "Can not open input file %s for reading.\n", source);
        return 1;
    }

    if ((outfile = fopen (dest, "wb")) == NULL)
    {
        fprintf (stderr, "Can not open output file %s for writing.\n", dest);
        fclose (infile);
        return 1;
    }

    while ((c = fgetc (infile)) != EOF)
    {
        if ((o = compress_otp()) == EOF)
        {
            fprintf (stderr, "Premature end of OTP file %s\n", otp_name);
            fclose (infile);
            fclose (outfile);
            crypt_key_erase();
            return 1;
        }
        c ^= o;
        if (fputc (c, outfile) == EOF)
        {
            fprintf (stderr, "Could not write to output file %s\n", dest);
            fclose (infile);
            fclose (outfile);
            return 1;
        }
    }

    /*
       Report output file name, OTP file name, original offset, and next
       offset. Then update offset for next file so that information within
       the OTP file is not reused as long as the main program does not exit.
    */
    printf ("%s %s %ld %ld\n", dest, otp_name, offset, otp_compression_count);
    offset = otp_compression_count;

    /* close everything and give a good return code */
    fclose (infile);
    fclose (outfile);
    return 0;
}

/* OTP file name, offset, and setup */

static int
validate_string (char *s)                        /* get otp_name and offset */
{
    char *p;
    int i = 0;
    long l = 0;

	 otp_compression_count = 0;						 /* clear OTP counters */
	 otpblock.count = 0;

    while ((*s == '\"') || (*s == ' '))          /* strip off leading quotes or spaces */
        s++;

    if (!isgraph (*s))                           /* non-printable is an error */
    {
        otp_name[0] = '\0';
        offset = 0;
        return 0;                                /* zero is error return */
    }

    while (isgraph (*s))                         /* form the file name from printables */
        otp_name[i++] = *s++;
    otp_name[i] = '\0';

    while (*s == ' ')                            /* strip off spaces */
        s++;

    p = s;
    while (isdigit (*s))                         /* make a long number from digits */
        l = (l * 10) + (long) (*s++ - '0');      /* zero if none.  Ignore rest of line */

    if (p == s)
        offset = check_key (otp_name, l);        /* set the offset */
    else
        offset = l;

    if ((otpfile = fopen (otp_name, "rb")) == NULL)   /* Can not open OTP file */
        return 0;

    if (compress_advance( offset ))              /* Error setting offset to OTP file */
        return 0;

    return 1;                                    /* one is good return */
}

void
key_update (void)
{
    char *s;
    char *tempname;
    char buffer[81];
    char foundname[81];
    long foundlength;
    FILE *fp;
    FILE *tfp;

    if ((fp = fopen (key_file_name, "r+")) == NULL)
        return;

    tempname = tempfile (key_file_name);
    if (tempname == NULL)
    {
        fprintf(stderr, "A temporary file for key update could not be created.\n");
        return;
    }
    if ((tfp = fopen (tempname, "w")) == NULL)
    {
        fprintf (stderr, "Can not open temporary key file %s for update\n", tempname);
        return;
    }
    
    for (s=otp_name; *s!='\0'; s++)
        if (islower(*s))
            *s = toupper(*s);
    fprintf (tfp, "%s %ld\n", otp_name, offset);

    while (fgets (buffer, 80, fp) != NULL)
    {
        if (sscanf (buffer, "%s %ld\n", foundname, &foundlength) == 2)
        {
            for (s=foundname; *s!='\0'; s++)
                if (islower(*s))
                    *s = toupper(*s);
            if (strcmp (otp_name, foundname))
                 fprintf (tfp, "%s %ld\n", foundname, foundlength);
        }
    }
    fclose (tfp);
    fclose (fp);
    remove (key_file_name);
    rename (tempname, key_file_name);
    
    return;
}

long
check_key (char *filename, long start)
{
    char buffer[81];
    char foundname[81];
    char *cPointer;
    int i;
    long foundlength = 0;
    FILE *fp;

    if ((fp = fopen (key_file_name, "r+")) == NULL)
        return start;

    while (fgets (buffer, 80, fp) != NULL)
    {
        if ((i = sscanf (buffer, "%s %ld\n", foundname, &foundlength)) != 0)
        {
            if (!strcmp (filename, foundname))
            {
                fclose (fp);
                if (i == 2)
                    return foundlength;
                else
                    return start;
            }
        }
    }
    fclose (fp);
    return start;
}

int
compress_otp( void )
{
    int status;

    if (!otpblock.count)
    {
        ziptemp.count = fread( ziptemp.buffer, sizeof(char), BLOCKSIZE, otpfile );
        if ( !ziptemp.count )
            return EOF;

        ziptemp.max = ziptemp.count;
		  otpblock.max = BLOCKSIZE;
        status = zipupblock( &ziptemp, &otpblock );
        if (status == -1)
        {
            fprintf(stderr, "Error compressing OTP file.\n");
            return EOF;
        }
        otpblock.max = otpblock.count;
    }

    if (otpblock.count)
	 {
	     otp_compression_count++;
        return otpblock.buffer[otpblock.max-(otpblock.count--)] & 0xff;
	 }

    return EOF;
}

int
compress_advance( long value )
{
    long l;

	 for (l=0; l<value; l++)
	     if (compress_otp() == EOF)
		      return 1;
	 return 0;
}

