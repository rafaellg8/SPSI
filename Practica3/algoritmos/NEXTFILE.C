/* nextfile.c */
/* Specific file name match with MSC under MSDOS */
/* Date and time routines are fixed.  Modify the code to change formats. */
/* Copyright 1985, 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */
 
/**
   Sequential calls to nextfile(s) with s as a pointer to a file
   name which may contain MSDOS wild cards will result in a return of a
   series of pointers to file names which match the argument name.
   Following the last file found - or if none are found -
   the function will return a NULL.  Each call to nextfile()
   will change the information in the previous string, so make a
   local copy of the string pointed to if it is needed again.

   Function p_find_t() returns a pointer to the find_t
   structure for the current file.  NULL is returned if none.

   Function date_found() returns a pointer to a formatted string
   with the date of the current file.  NULL on no current file.

   Function time_found() returns a pointer to a formatted string
   with the time of the current file.  NULL on no current file.

   Function flush_find() will reset the nextfile() function to
   look for the first file in the pattern that follows.  This is
   automatically done when NULL is returned by nextfile() to
   indicate that no more files match the current pattern.  The
   flush_find() function is only necessary when you want to restart
   searching for files matching a pattern before all matched files
   have been returned by nextfile().

   Function another_file() will return TRUE if there will be another
   file available after this one, and FALSE if not.  A FALSE return
   from this function does not call flush_find().   A call to this
   function is valid only after a non-NULL return from nextfile().
   Otherwise, an error (-1) return will result.
*/

#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <errno.h>
#include <dos.h>
#include <io.h>

#include "nextfile.h"

#ifndef TRUE
#define TRUE  (1)
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

static struct find_t file[2];

static int find_status[2] =
{0, 0};

static char name_buffer[129];
static char date_buffer[30];
static char time_buffer[30];

static char *month[] =
{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

char *
nextfile (char *s)                               /* return a pointer to the next name */
{
    if (*s == '\0')
    {                                            /* if there is no string, */
        flush_find ();                           /* reset this function and */
        return NULL;                             /* return NULL */
    }
    name_buffer[128] = '\0';                     /* force string termination */

    if (strcmp (name_buffer, s))                 /* if the file name is new, */
    {
        strcpy (name_buffer, s);                 /* copy the name to the save buffer */
        if (_dos_findfirst (name_buffer, 0, &file[0]))
        {
            flush_find ();                       /* non-zero is an error */
            return NULL;
        }
        file[1]=file[0];
        if (_dos_findnext (&file[1]))            /* look ahead for next name */
            find_status[1] = FALSE;              /* set next file status */
        else
            find_status[1] = TRUE;
        find_status[0] = TRUE;                   /* set current file status */
        return (file[0].name);                   /* for no error, return a name pointer */
    }
    else
    {
        if (find_status[1] == FALSE)             /* for no next name, flush and end */
        {
            flush_find ();
            return NULL;
        }
        file[0] = file[1];                       /* current file updated */
        if (_dos_findnext (&file[1]))            /* look ahead for next name */
            find_status[1] = FALSE;              /* set next file status */
        else
            find_status[1] = TRUE;
        find_status[0] = TRUE;                   /* set current file status */
        return (file[0].name);                   /* return a name pointer */
    }
}

struct find_t *
p_find_t ()                                      /* found file structure address */
{
    if (find_status[0])                          /* if last find a success, */
        return (&file[0]);                       /* return pointer */
    return (NULL);                               /* else return NULL */
}

char *
date_found ()
{
    if (find_status[0])                          /* for a current file */
    {                                            /* return formatted string */
        sprintf (date_buffer, "%2.2d-%s-%02.2d",
                 file[0].wr_date & 0x1f,
                 month[((file[0].wr_date >> 5) & 0x0f) - 1],
                 (file[0].wr_date >> 9) + 80);
        return date_buffer;
    }
    return NULL;                                 /* else return NULL */
}

char *
time_found ()
{
    int h,
     m;

    if (find_status[0])                          /* for a current file */
    {                                            /* return a formatted string */
        h = (file[0].wr_time >> 11) & 0x1f;
        m = (file[0].wr_time >> 5) & 0x3f;
        sprintf (time_buffer, "%2.2d:%02.2d %cm",
                 (h % 12) ? (h % 12) : 12, m, h > 11 ? 'p' : 'a');
        return time_buffer;
    }
    return NULL;                                 /* else return NULL */
}

void
flush_find (void)
{
    find_status[0] = FALSE;
    find_status[1] = FALSE;
    name_buffer[0] = '\0';
    return;
}

int
another_file (void)
{
    if (find_status[0] == TRUE)
        return (find_status[1]);
    else
        return ERROR;
}
