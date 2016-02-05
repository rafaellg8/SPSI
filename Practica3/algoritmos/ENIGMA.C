/* enigma.c */
/* enigma encryption cipher from Henry Tieman implementation */
/* Unless otherwise noted Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* under MSDOS, NMAKE /F ENIGMA.MAK all clean */

#include <stdio.h>
#include <stdlib.h>
#include "crypt.h"

/*
  This routine uses the common interface to CRYPT.C. 
  Generally, the name of this module becomes the name
  of the executable file.
*/

void init_mach (void);
int encipher (int);

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

static int key_defined = 0;                      /* Set to 1 after a valid key has been defined */
static int encrypt_or_decrypt = ENCRYPTION_SELECT;

/* Define SAVE_CASE to (0) for all upper case, and to (1) to retain case */
#define SAVE_CASE (1)

/* key information */

#define NUM_ROTORS 5

static char ref_rotor[27] = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

static char rotor[NUM_ROTORS][27] =
{                                                /* pre defined rotors */
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "ESOVPZJAYQUIRHXLNFTGKDCMWB",
    "VZBRGITYUPSDNHLXAWMJQOFECK",
};

static int step_data[NUM_ROTORS] =
{
    16, 4, 21, 9, 25                             /* steps at: q, e, v, j, z */
};

/*
 * enigma key default settings
 */

static int order[3] =
{0, 1, 2};                                       /* rotor order, user input is +1 */
static char ring[8] =
{                                                /* ring settings */
    '\0', 'A', 'A', 'A',                         /* default: AAA */
    '\0', '\0', '\0', '\0'};
static int n_plugs = 0;                          /* number of plugs */
static char plugs[80] = "";                      /* plug string */
static int pos[3] =
{0, 0, 0};                                       /* rotor positions */

/*
 * simulation data and machine state data
 */

static int data[8][26];                          /* working array for machine */
static int rdata[8][26];                         /* reverse array */
static int step[3];                              /* steps coresponding to rotors */
static int double_step;                          /* rotor 2 step twice */

/*
   cipher_doc:
   This array of strings must have two sections:
   CIPHER that describes the cipher used and
   KEY that describes how the key is defined and entered.
*/

static char *cipher_doc[] =
{
    "CIPHER",
    "      The ENIGMA cipher uses multiple rotors.  It was originally",
    "      implemented as a mechanical rotor device, and was used by",
    "      Germany during the second World War.  Each rotor moves at a",
    "      different rate, giving a large period for the combination.",
    "      This version retains upper and lower case.",
    "",
    "KEY",
    "      A key file name is expected as the argument for the -k option.",
    "",
    "      The key contains the following information:",
    "          n n n         - for rotor order (1 to 5)",
    "          x x x         - for ring setting, x is a letter",
    "          n             - Number of plugs (0 to 13)",
    "          xx xx xx ...  - Plug letter pairs, one for each n",
    "          x x x         - initial rotor position, x is a letter",
    "",
    "      If the '-k ?' option is given, or if there is no key file,",
    "      you will be prompted for key data.",
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
    FILE *fp;                                    /* input file */
    int num;                                     /* dummy returned from fscanf() */
    int idx;                                     /* index/counter */
    char a[4];                                   /* dummy for input */
    char buffer[132];                            /* used with sscanf */

    if (key_type == KEY_FILE)                    /* a file name has been given */
    {
        if ((fp = fopen (key_text, "r")) == NULL)
        {
            key_defined = 0;
            return 0;
        }
        num = fscanf (fp, "%d %d %d\n", &order[0], &order[1], &order[2]);
        num = fscanf (fp, "%c %c %c\n", &ring[1], &ring[2], &ring[3]);
        num = fscanf (fp, "%d\n", &n_plugs);
        if (n_plugs != 0)
        {
            num = fscanf (fp, "%[^\n]\n", plugs);
        }
        num = fscanf (fp, "%c %c %c\n", &a[0], &a[1], &a[2]);
        for (idx = 0; idx < 3; idx++)
        {
            (order[idx])--;
            ring[idx + 1] = toupper (ring[idx + 1]);
            pos[idx] = toupper (a[idx]) - 'A';
        }
        fclose (fp);
        key_defined = 1;
        return 0;
    }
    else if (key_type == KEY_IMMEDIATE)          /* a key string has been given */
    {
        if (!strcmp (key_text, "?"))             /* prompt for key */
        {
            printf ("Rotor order (3 numbers from 1 to 5 separated by spaces): ");
            (void) gets(buffer);
            num = sscanf (buffer, "%d %d %d", &order[0], &order[1], &order[2]);
            printf ("Ring settings (3 letters separated by spaces): ");
            (void) gets(buffer);
            num = sscanf (buffer, "%c %c %c", &ring[1], &ring[2], &ring[3]);
            printf ("Number of plugs (number from 0 to 13): ");
            (void) gets(buffer);
            num = sscanf (buffer, "%d", &n_plugs);
            if (n_plugs != 0)
            {
                printf ("Plug letter pairs (one pair per plug): ");
                (void) gets(buffer);
                num = sscanf (buffer, "%[^\n]", plugs);
            }
            printf ("Initial rotor position (3 letters separated by spaces): ");
            (void) gets(buffer);
            num = sscanf (buffer, "%c %c %c", &a[0], &a[1], &a[2]);
            for (idx = 0; idx < 3; idx++)
            {
                (order[idx])--;
                ring[idx + 1] = toupper (ring[idx + 1]);
                pos[idx] = toupper (a[idx]) - 'A';
            }
            key_defined = 1;
            return 0;
        }
        else
            return crypt_key (KEY_FILE, key_text);
    }
    fprintf (stderr, "Error getting key\n");
    exit (1);
}

/*
   crypt_key_erase:
   If a local copy of the key has been made, erase it from memory.
   This increases security for the key can not be obtained from
   an examination of memory.
*/

void
crypt_key_erase ()
{
    int i;

    order[0] = 0;
    order[1] = 1;
    order[2] = 2;
    for (i = 0; i < 8; i++)
        ring[i] = '\0';
    for (i = 1; i < 4; i++)
        ring[i] = 'A';
    n_plugs = 0;
    for (i = 0; i < 80; i++)
        plugs[i] = '\0';
    pos[0] = 0;
    pos[1] = 0;
    pos[2] = 0;
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
    char *s;
    int c;
    int case_char;
    FILE *infile;
    FILE *outfile;

    while (!key_defined)
        crypt_key (KEY_IMMEDIATE, "?");

    init_mach ();

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

    while ((c = fgetc (infile)) != EOF)
    {
        if (isalpha (c))                           /* only letters changed */
        {
            case_char = c;
            c = encipher ((int) (toupper (c)));    /* and with a loss of case */
            if (SAVE_CASE && islower(case_char))   /* restore case if requested */
                c = tolower(c);
        }
        if (fputc (c, outfile) == EOF)
        {
            fprintf (stderr, "Could not write to output file %s\n", dest);
            fclose (infile);
            fclose (outfile);
            return 1;
        }
    }

    fclose (infile);
    fclose (outfile);
    return 0;
}

/*
 * init_mach - set up data according to the input data
 */

static void
init_mach (void)
{
    int i, j;                                    /* indices */
    int ds;                                      /* used during ring settings */
    int u, v;                                    /* temps for plugboard input */

    /* setup rotor data */
    for (j = 0; j < 26; j++)
        data[4][j] = ((int) ref_rotor[j] - 'A' + 26) % 26;

    for (i = 1; i < 4; i++)
    {
        step[i - 1] = step_data[order[i - 1]];
        for (j = 0; j < 26; j++)
        {
            data[i][j] = ((int) (rotor[order[i - 1]][j]) - 'A' + 26) % 26;
            data[8 - i][data[i][j]] = j;
        }
    }

    /* setup ring settings */
    ring[7] = ring[1];
    ring[6] = ring[2];
    ring[5] = ring[3];
    for (i = 1; i < 8; i++)
        if (i != 4)
        {
            ds = (int) (ring[i]) - 'A';
            if (ds != 0)
            {
                for (j = 0; j < 26; j++)
                    data[0][j] = data[i][j];
                for (j = 0; j < 26; j++)
                    data[i][j] = data[0][(26 - ds + j) % 26];
            }
        }

    /* setup plug data */
    if (n_plugs != 0)
    {
        j = 0;
        for (i = 0; i < 26; i++)
            data[0][i] = i;
        for (i = 0; i < n_plugs; i++)
        {
            while (!isalpha (plugs[j]))
            {
                j++;
                if (plugs[j] == '\0')
                    break;
            }
            u = toupper (plugs[j++]) - 'A';
            v = toupper (plugs[j++]) - 'A';
            data[0][u] = v;
            data[0][v] = u;
        }
    }

    /* convert all moving rotor data to displacements */
    for (i = 1; i < 8; i++)
    {
        if (i != 4)
            for (j = 0; j < 26; j++)
                data[i][j] = (data[i][j] - j + 26) % 26;
    }

    /* compute reverse */
    if (n_plugs != 0)
        for ( i=0; i<26; i++ )
            rdata[0][(data[0][i])%26] = i;

    for ( i=0; i<26; i++ )
        rdata[4][(data[4][i])%26] = i;

    for ( i=1; i<8; i++ )
        if (i != 4)
            for ( j=0; j<26; j++ )                       
                rdata[i][(j + data[i][j])%26] = j; 
  
    /* setup rotor starting positions */
    double_step = FALSE;                         /* no previous rotor position */
    /* input function has already done the rotor positions */
}

/*
 *  encipher - c implementation of the enigma cipher function
 */

static int
encipher (int c)
{
    int j;                                       /* index for counting */
    int idx;                                     /* rotor index */

    if (isalpha (c))
    {
        pos[0] = (pos[0] + 1) % 26;              /* first, advances the rotors */
        if (pos[0] == step[0])
            pos[1] = (pos[1] + 1) % 26;
        if (double_step)
        {
            pos[1] = (pos[1] + 1) % 26;
            pos[2] = (pos[2] + 1) % 26;
            double_step = FALSE;
        }
        if (pos[1] == step[1])
            double_step = TRUE;

        c -= 'A';                                /* start to encipher */
        if (encrypt_or_decrypt  == ENCRYPTION_SELECT)
        {
            if (n_plugs != 0)
                c = data[0][c];
            for (j = 0; j < 3; j++)                  /* do rotors forward */
            {
                idx = (c + pos[j]) % 26;
                c = (c + data[j + 1][idx]) % 26;
            }
            c = (data[4][c]) % 26;                   /* reflecting rotor */
            for (j = 0; j < 3; j++)                  /* do rotors reverse */
            {
                idx = (c + pos[2 - j]) % 26;
                c = (c + data[j + 5][idx]) % 26;
            }
            if (n_plugs != 0)
                c = data[0][c];
        }
        else
        {
            if (n_plugs != 0)
                c = rdata[0][c];

            for (j=2; j>=0; j--)
                c = ( 26 + rdata[j + 5][(c + pos[2 - j]) % 26 ] - pos[2 - j] ) %26;

            c = rdata[4][c] % 26;

            for (j=2; j>=0; j--)
                c = ( 26 + rdata[j + 1][(c + pos[j]) % 26 ] - pos[j] ) %26;

            if (n_plugs != 0)
                c = rdata[0][c];
        }
        c += 'A';
    }
    return (c);
}
