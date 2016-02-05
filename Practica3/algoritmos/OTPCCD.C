/* otpccd.c */
/* XOR with the data on a CDROM used as a one time pad with input 
   including absolute starting sector and offset within a sector.
	The CDROMC module compresses OTP data from the CDROM. */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F OTPCCD.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "tempfile.h"
#include "cdromc.h"

/*
  This routine uses the common interface to CRYPT.C.
  Generally, the name of this module becomes the name
  of the executable file.
*/

static int key_defined = 0;                      /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;
static char key_string[257];

/* module specific */

static char otp_name[80] = {'\0'};
static long sector;
static int offset;
int validate_string (char *);
static char key_file_name[80];

void key_update (void);
void check_key (char *);

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[] =
{
    "CIPHER",
    "      This program performs an EXCLUSIVE OR operation between a file",
    "      and the contents of a CDROM used as a one time pad (OTP).",
    "      The data on the CDROM is compressed before it is used.",
    "      Failure occurs if the end of the CDROM is reached.  The",
    "      cipher does not require the -d option.  After each file",
    "      is processed, a line is output with decryption information:",
    "      output file name, OTP CDROM label, OPT sector, OTP offset,",
    "      and next sector and offset.  This can be redirected to a file.",
    "      It is very important to keep this information for decyrption.",
    "      If the key file exists, it will be updated.",
    "",
    "KEY",
    "      The key is an ASCII string, given as \"CDROM_ID SECTOR OFFSET\"",
    "      where the CDROM_ID is the volume label of the CDROM that you",
    "      have selected to use as a one time pad.  If the label contains",
    "      all numbers, a drive designation is required.  The SECTORs are",
    "      numbered from 1 to just over 300000 for a completely full CDROM.",
    "      If the SECTOR is not given, a starting value of 1 is used.",
    "      The OFFSET is the byte offset within a sector and goes from 0",
    "      to 2047.  It may not be given unless the SECTOR is also defined.",
    "      If the OFFSET is not given, a value of 0 is used.  If two numbers",
    "      are given, they are taken as SECTOR and OFFSET.  If only one",
    "      number is given, it is taken as the SECTOR.  On the command line,",
    "      enclose the key string within quotes.  To use the CDROM in the",
    "      first CDROM drive without naming it, give \"*\" as the CDROM label.",
    "",
    "      If a key file exists, the first line is read, and it is scanned",
    "      for the CDROM label, sector, and offset.  If you also give a",
    "      CDROM label but no sector for the key on the command line, the key",
    "      file will be searched for a sector and offset.  If you give a",
    "      CDROM label, sector and offset on the command line for the key,",
    "      this overrides any information in the key file.  Do not use",
    "      quotes in the key file.  If the key file is read-only, it will",
    "      be completely ignored to prevent repeated use of the same pad.",
    "      An empty key file should not be created.",
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
        key_defined = 0;
        key_update ();
    }

    for (i = 0; i < 257; i++)
        key_string[i] = '\0';
    offset = 0;
    sector = 0L;
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
    int iOffset;
    unsigned long lSector;
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
        if ((o = CD_char()) == -1)
        {
            fprintf (stderr, "End of OTP CDROM %s\n", otp_name);
            fclose (infile);
            fclose (outfile);
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
       Report output file name, OTP volume ID, original sector, original 
       offset, next sector, and next offset.
    */
    iOffset = get_CD_offset();
    lSector = get_CD_sector();
    printf ("%s %s %ld %d %ld %d\n", dest, otp_name, 
           sector, offset, lSector, iOffset);
    sector = lSector;
    offset = iOffset;

    /* close everything and give a good return code */
    fclose (infile);
    fclose (outfile);
    return 0;
}

/* Evaluate string and initialize CDROM */

static int
validate_string (char *s)                        /* get otp_name and offset */
{
    char buffer[257];
    char disk = '\0';
    char *p;
    int i;
    int gotSector;
    int gotAlpha;
    unsigned long l;

    while ((*s == '\"') || (*s == ' '))          /* strip off leading quotes or spaces */
        s++;

    if (*s == '\0')                              /* no label is an error */
    {
        otp_name[0] = '\0';
        sector = 0L;
        offset = 0;
        return 0;                                /* zero is error return */
    }

    l = 0L;
    for (i=0, gotAlpha=0; isgraph (*s) && (*s != '\"'); i++)    /* form the volume ID from printables */
    {
        buffer[i] = *s++;
        if (islower(buffer[i]))
            buffer[i] = toupper(buffer[i]);
        if (!isdigit(buffer[i]))
            gotAlpha=1;
        if (!gotAlpha)                          /* if it's a number, get it */
            l = (l * 10L) + (long) (buffer[i] - '0');
    }
    buffer[i] = '\0';

    if (gotAlpha)                                /* got alphabetics */
    {
        if (buffer[1] != ':')                    /* check for disk designation */
            strcpy( otp_name, buffer );
        else
        {
            disk = buffer[0];                    /* got a disk drive */
            strcpy( otp_name, &buffer[2] );
        }
    }

    if (otp_name[0] == '\0')                    /* no name by this point is an error */
    {
        otp_name[0] = '\0';
        sector = 0L;
        offset = 0;
        return 0;                                /* zero is error return */
    }

    while (*s == ' ')                            /* strip off spaces */
        s++;

    if (gotAlpha)
        for( l=0L; isdigit (*s); s++)            /* make a long number from digits */
            l = (l * 10L) + (long) (*s - '0');

    if (l == 0L)                                 /* set the sector */
    {
        sector = 1L;
        gotSector = 0;
    }
    else
    {
        sector = l;
        gotSector = 1;
    }

    while (*s == ' ')                            /* strip off spaces */
        s++;

    for( i=0; isdigit (*s); s++)                 /* make a number from digits */
        i = (i * 10) + (int) (*s - '0');

    offset = i;                                  /* set the offset */

    /* initialize CDROM */

    if (!gotSector && strcmp("*",otp_name))      /* check for sector/offset */
        check_key(otp_name);

    if ((p=CD_read_ID( disk )) == NULL)
    {
        otp_name[0] = '\0';
        sector = 0L;
        offset = 0;
        return 0;                                /* zero is error return */
    }   /* CD initialized */

    if (!strcmp("*",otp_name))                  /* if not specified, use default */
    {
        strcpy(otp_name, p);
        if (!gotSector)
            check_key(otp_name);
    }

    if (CD_read_sector(otp_name, sector) == NULL)
    {
        otp_name[0] = '\0';
        sector = 0L;
        offset = 0;
        return 0;                                /* zero is error return */
    }   /* sector set */

    if (CD_offset(offset) == -1)                 
    {                                            
        otp_name[0] = '\0';
        sector = 0L;
        offset = 0;
        return 0;                                /* zero is error return */
    }   /* offset defined */

    return 1;                                    /* one is good return */
}

void
key_update (void)
{
    char *s;
    char *tempname;
    char buffer[81];
    char foundname[81];
    int  i;
    int  foundoffset;
    long foundsector;
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
    fprintf (tfp, "%s %ld %d\n", otp_name, sector, offset);

    while (fgets (buffer, 80, fp) != NULL)
    {
        if (i = sscanf (buffer, "%s %ld %d\n", foundname, &foundsector, &foundoffset))
        {
            for (s=foundname; *s!='\0'; s++)
                if (islower(*s))
                    *s = toupper(*s);
            if (i < 3)
                foundoffset = 0;
            if (i < 2)
                foundsector = 1L;
            if (strcmp (otp_name, foundname))
                 fprintf (tfp, "%s %ld %d\n", foundname, foundsector, foundoffset);
        }
    }
    fclose (tfp);
    fclose (fp);
    remove (key_file_name);
    rename (tempname, key_file_name);
    
    return;
}

void
check_key (char *label)
{
    char buffer[81];
    char foundname[81];
    char *cPointer;
    int i;
    int foundoffset = 0;
    long foundsector = 1;
    FILE *fp;

    if ((fp = fopen (key_file_name, "r+")) == NULL)
        return;

    while (fgets (buffer, 80, fp) != NULL)
    {
        if ((i = sscanf (buffer, "%s %ld %d\n", foundname, &foundsector, &foundoffset)) != 0)
        {
            for (cPointer=foundname; *cPointer; cPointer++)
                if(islower(*cPointer))
                    *cPointer = toupper(*cPointer);
            if (!strcmp (label, foundname))
            {
                fclose (fp);
                if (i >= 2)
                {
                    sector = foundsector;
                    offset = 0;
                }
                if (i >= 3)
                    offset = foundoffset;
                return;
            }
        }
    }
    fclose (fp);
    return;
}
