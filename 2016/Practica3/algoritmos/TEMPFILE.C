/* tempfile.c */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/* Find a temporary file than can be opened for write,
   that does not exist, and that differs from the
   argument only by the file extension.  A pointer to
   the name will be returned.  Return NULL on failure.
   Running this from a read-only medium will always fail.
 
   Only 12 different file extensions are tried.  If you
   fail to erase the temporary file after using it, the 
   routine will fail after the finite number of files
   are created with the same base name in the same
   subdirectory.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tempfile.h"

static char found_name[81];

char *
tempfile (char *name)
{
    char **ePointer;
    char *extensions[] =                         /* trial extensions for temp file */
    {                                            
     "TMP",
     "T01",
     "X78",
     "ZXY",
     "H4D",
     "V9Y",
     "001",
     "040",
     "963",
     "826",
     "543",
     "195",
     NULL
    };
    char t_name[81];
    FILE * fPointer;

    if (strlen (name) > 76)                      /* too long */
        return NULL;
    strcpy (t_name, name);                       /* get local copy of name */
    if (strrchr (t_name, '.') != NULL)           /* delete extension */
        *strrchr (t_name, '.') = '\0';
    strcat (t_name, ".");                        /* t_name now has no extension */

    for (ePointer = extensions; *ePointer != NULL; ePointer++)
    {
        strcpy (found_name, t_name);
        strcat (found_name, *ePointer);
        if ((fPointer = fopen (found_name, "r")) == NULL)
            break;
        else
            fclose (fPointer);
    }

    if (*ePointer == NULL)               /* end of list, failure */
        return NULL;
    
    if ((fPointer = fopen (found_name, "w")) == NULL)
        return NULL;
    fclose(fPointer);

    remove (found_name);

    return found_name;
}

