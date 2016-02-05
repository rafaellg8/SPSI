/* cdromc.c */
/* interface to the sectors on a CDROM with compression */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

#include <stdio.h>
#include <stdlib.h>
#include <dos.h>

#include "cdromc.h"

#ifdef CD_COMPRESS
#include "zblock.h"
#endif

static int compress_CD_data(void);
static unsigned char CD_data[2048];
static unsigned char CD_ID[38];
static unsigned long CD_sector = 0;
static int CD_index = 0;
static int CD_count = 0;
static int valid_drive_ID;
static int ID_OK = 0;
static struct find_t file;

/*
   CD_read_sector:

   Read the sector indicated of the CDROM with the given ID.
   If there is fail to read, the return will be a NULL pointer.  
   On success, return a pointer to the 2048 byte data array.
*/

unsigned char *
CD_read_sector (char *volID, unsigned long sector)
{
    void __far *p;
    struct _SREGS segregs;
    union _REGS inregs;
    union _REGS outregs;
    union Long2Word
    {
        unsigned long sector;
        unsigned int word[2];
    } start;

    if (ID_OK == 0)
    {
        fprintf (stderr, "CDROM volume ID not initialized.\n");
        return NULL;
    }

    if (strcmp (volID, CD_ID))                  /* CDROM volume ID does not match */
        return NULL;

    /* read the sector */
    start.sector = sector;                       /* setup sector number */
    _segread (&segregs);                         /* setup segment registers */
    inregs.x.ax = 0x1508;                        /* setup for CDROM sector read */
    inregs.x.di = start.word[0];
    inregs.x.si = start.word[1];
    inregs.x.cx = valid_drive_ID;
    inregs.x.dx = 1;
    p = CD_data;
    inregs.x.bx = _FP_OFF (p);
    segregs.es = _FP_SEG (p);
    (void) _int86x (0x2f, &inregs, &outregs, &segregs);
    if (outregs.x.cflag)
    {
        fprintf (stderr, "Error reading CDROM sector data.\n");
        return NULL;
    }
    CD_count = 2048;
    CD_sector = sector;
    if (compress_CD_data())
        return NULL;
    return CD_data;
}

/*
   CD_read_ID:

   The drive_letter (e.g. 'D' or 'e') designates the CDROM drive.
   For only one or the first CDROM drive, set drive_letter to '\0'.
   Get the volume ID and save in CD_ID.  Set ID_OK to 1 and return a
   pointer to CD_ID.  If the volume ID can not be read or there is no
   CDROM in the drive, set ID_OK to zero and return a NULL pointer.
   An error message to stderr will also be generated.
*/

unsigned char *
CD_read_ID (char drive_letter)
{
    char *name;
    char *drive = "C:\\*.*";
    char *s;
    int drive_count;
    int i;
    int k;
    unsigned int seg;
    unsigned int off;
    void __far *p;
    struct _SREGS segregs;
    union _REGS inregs;
    union _REGS outregs;

    ID_OK = 0;                                   /* invalid until proven */

    /* Check for first valid CDROM drive letter on system */
    _segread (&segregs);                         /* setup segment registers */
    inregs.x.ax = 0x1500;
    inregs.x.bx = 0;                             /* check that MSCDEX is installed */
    (void) _int86x (0x2f, &inregs, &outregs, &segregs);
    if ((drive_count = outregs.x.bx) == 0)       /* insure that MSCDEX is installed */
    {
        fprintf (stderr, "MSCDEX is not installed.\n");
        ID_OK = 0;
        return NULL;
    }
    valid_drive_ID = outregs.x.cx;               /* get first CDROM drive letter */

    /* Check if CDROM designated by letter such as 'D' */
    if (drive_letter)
    {
        if (!isalpha (drive_letter))
        {
            fprintf (stderr, "Invalid drive designation: %c.\n", drive_letter);
            ID_OK = 0;
            return NULL;
        }
        valid_drive_ID = toupper (drive_letter) - 'A';
    }

    /* Check that this drive is supported by MSCDEX */
    _segread (&segregs);                         /* setup segment registers */
    inregs.x.ax = 0x150b;
    inregs.x.bx = 0;
    inregs.x.cx = valid_drive_ID;
    (void) _int86x (0x2f, &inregs, &outregs, &segregs);
    if (outregs.x.ax == 0 || outregs.x.bx != 0xadad)
    {
        fprintf (stderr, "%c: is not a CDROM drive.\n", toupper (drive_letter));
        ID_OK = 0;
        return NULL;
    }

    /* Get CDROM vol ID from DOS find first file function */
    drive[0] = valid_drive_ID + 'A';
    if (_dos_findfirst (drive, _A_VOLID, &file))
    {
        printf("Could not get CDROM volume ID from DOS find first: %s\n", drive);
        ID_OK = 0;
        return NULL;
    }
    else
    {
        name = file.name;
        for (i=0; i<13; )
        {
            if (*name == '.')
                name++;
            CD_ID[i++] = *name++;
            if (*name == '\0')
                break;
        }
        CD_ID[i] = '\0';
    }

    ID_OK = 1;
    CD_sector = 0;
    CD_index = 0;
    return CD_ID;
}

/* 
    Perform buffered reading of characters from the CDROM:
 
    CD_char: get the next character, going to the next sector if needed.
    Return the unsigned character or 0xffff upon error.  Using this
    routine, it is only necessary to call CD_read_ID and then 
    CD_read_sector to setup the first sector to read.

    CD_offset: set the starting location for reading within the current 
    sector. Values may range from 0 to 2047.  Return the value set or
    0xffff upon error.  Performing CD_read_ID always sets the offset
    to zero.  So, issue this command after calling CD_read_ID.  If 
    there is an error, offset is set to zero. The offset is actually
    could go over 2047.  But if it exceeds the count of characters
    remaining in the current sector, it will continue counting into
    the next sector.  Use get_CD_sector and get_CD_offset to find out 
    the real sector and offset after this command.  This is especially
    inportant for the compressed code that has variable compressed
    sector lengths.

    get_CD_sector: returns currently selected sector.

    get_CD_offset: returns next character position.
*/


int
CD_offset( int offset )
{
    int i = 0;

    while ( i++ < offset )
        if (CD_char() == -1)
        {
            fprintf( stderr, "Offset out of range.\n");
            CD_sector = 0;
            CD_index = 0;
            return -1;
        }
    return CD_index;
}

unsigned int
CD_char( void )
{
    if (ID_OK == 0)
    {
        fprintf(stderr, "CDROM ID not initialized.\n");
        return 0xffff;
    }
    if (CD_sector == 0)
    {
        fprintf(stderr, "CDROM sector not selected.\n");
        return 0xffff;
    }
    if (CD_index != CD_count)
        return (unsigned int) CD_data[CD_index++];
    if (CD_read_sector(CD_ID, ++CD_sector) == NULL)
        return 0xffff;
    if (compress_CD_data())
        return 0xffff;
    CD_index = 0;
    return (unsigned int) CD_data[CD_index++];
}

unsigned long
get_CD_sector( void )
{
    return CD_sector;
}

int
get_CD_offset( void )
{
    return CD_index;
}


static int 
compress_CD_data(void)
{
#ifdef CD_COMPRESS
    int i;
    struct zipblock in;
    struct zipblock out;

    in.count = in.max = out.max = CD_count;
    for (i=0; i<CD_count; i++)
        in.buffer[i] = CD_data[i];
    if (zipupblock( &in, &out ) == -1)
    {
        fprintf(stderr, "Failure to compress block\n");
        return -1;
    }
    CD_count = out.count;
    for (i=0; i<CD_count; i++)
        CD_data[i] = out.buffer[i];
#endif
    return 0;
}



