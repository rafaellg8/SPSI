/* crypt.c */
/* Main program for cryptography */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

/*
  Under MSDOS, this main module provides the interface to various
  encryption / decryption schemes.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <graph.h>
#include <sys\types.h>
#include <sys\stat.h>
#include "crypt.h"
#include "getopt.h"
#include "nextfile.h"
#include "tempfile.h"

/* Documentation for help */
extern char *documentation[];

/* Program name */
char *prog;

/* crypt key file name */
char crypt_key_name[_MAX_PATH];

/* Overwrite number for deleted input files with -G */
int overwrite = 0x55;

/* Fate of input file with -o */
int delete_mode = DELETE_NORMAL;  

/* zero file name structure to initialize new file searches */
struct fnames zero_files =
{
    (struct fnames *) 0,
    {'\0','\0','\0','\0','\0','\0',
     '\0','\0','\0','\0','\0','\0','\0'}
} ;                              

int
main(int argc, char *argv[])
{
    char sDrive[_MAX_DRIVE];
    char sDir[_MAX_DIR];
    char sFname[_MAX_FNAME];
    char sExt[_MAX_EXT];
    char *s;
    int i;
    FILE *pfile;

    /* Make needed file names */
    if ( _fullpath( crypt_key_name, argv[0], 128 ) == NULL )
    {
        fprintf( stderr, "Could not create full program path name\n");
        usage();
        exit( 1 );
    }

    /* Get path components */
    _splitpath( crypt_key_name, sDrive, sDir, sFname, sExt );
    if ( strrchr( crypt_key_name, '.' ) != NULL )               /* delete extension */
        *strrchr( crypt_key_name, '.' ) = '\0';
    strcat( crypt_key_name, ".KEY" );
    for ( s=crypt_key_name; *s; s++ )                           /* make name upper case */
        if ( islower( *s ) )
            *s = toupper( *s );
    prog = sFname;
    for ( s=prog; *s; s++ )                                     /* make name lower case */
        if ( isupper( *s ) )
            *s = tolower( *s );

    /* Do usage in case there are no arguments */
    if ( argc == 1 )
    {
        usage();
        exit( 0 );
    }

    /* give help if requested */
    if ( give_help( argc, argv ) )
        exit( 0 );

    /* process crypt key file name */
    (void) crypt_key( KEY_FILE, crypt_key_name );

    /* setup defaults */
    (void) crypt_select( ENCRYPTION_SELECT );

    /* process all the arguments in one line */
    nextline( argc, argv );  

    /* erase key from memory */
    crypt_key_erase();

    exit( 0 );
}

/*
    nextline:
    First, process help.
    Then, process all options.
    Then, process files for encryption.
    Finally, process commands from a file is -f given.
*/

void
nextline( int argc, char *argv[] )
{
    char command_file_name[128];       /* command file name from -f */
    char output_file_name[128];        /* output file name from -o */
    char temporary[128];               /* temporary storage */
    char full_file_name[128];          /* constructed file name */
    char full_argv_name[_MAX_PATH];    /* set sizes for _splitpath */
    char sDrive[_MAX_DRIVE];
    char sDir[_MAX_DIR];
    char sFname[_MAX_FNAME];
    char sExt[_MAX_EXT];
    char buffer[513];                  /* input line */
    char *next_file_name;              /* pointer to next file name */
    char *cPointer;
    int c;
    FILE *fPointer;
    struct fnames new_files;
    struct fnames *fnPointer;

    if ( argc == 1 )
        return;

    /* give help if requested */
    if ( give_help( argc, argv ) )
        return;

    /* initialize the file names */
    command_file_name[0] = '\0';
    output_file_name[0] = '\0';

    /* Process all options */
    opterr = 0;
    optind = 0;
    while ((c = getopt (argc, argv, "edcgGqQf:k:#:o:")) != EOF)
        switch (c)
        {
          case '?':                              /* unidentified option */
            usage();
            exit(1);
            break;

          case 'e':
            (void) crypt_select( ENCRYPTION_SELECT );
            break;

          case 'd':
            (void) crypt_select( DECRYPTION_SELECT );
            break;

          case 'c':
            copyright();
            break;

          case 'q':                              /* normal delete */
            delete_mode = DELETE_NORMAL;
            break;

          case 'Q':
            delete_mode = DELETE_ALL_NORMAL;     /* quick delete, all input files */
            break;

          case 'g':
            delete_mode = DELETE_DOD;            /* DOD delete mode */
            break;

          case 'G':
            delete_mode = DELETE_ALL_DOD;        /* DOD delete, all input files */
            break;

          case 'f':                              /* get command input from file */
            if (command_file_name[0])            /* do this only once per line */
            {
                fprintf( stderr, "Error: Two -f commands on one line\n");
                usage();
                exit(1);
                break;
            }
            strcpy( command_file_name, optarg );
            break;

          case 'k':                              /* get encryption key */
            crypt_key( KEY_IMMEDIATE, optarg );
            if (!strcmp(optarg, "?"))
                _clearscreen(_GCLEARSCREEN);
            break;

          case '#':                              /* get overwrite for -d or -D */
            if (sscanf( optarg, "%d", &overwrite ) != 1)
            {
                fprintf( stderr, "Error: Failure to set overwrite number %d\n", optarg);
                usage();
                exit( 1 );
            }
            overwrite &= 255;
            break;

          case 'o':                              /* get output file name */
            if (output_file_name[0])
            {
                fprintf( stderr, "Error: Two -o commands on one line.\n");
                usage();
                exit(1);
                break;
            }
            strcpy( output_file_name, optarg );
            break;

          default:                               /* This can't happen. */
            fprintf (stderr, "%s: Option parse failure\n", prog);
            usage();
            exit(1);
            break;
        }

    /* Process all input files */
    if ( output_file_name[0] )                   /* if -o option given, process it */
    {   
        if (argc - optind == 1)                  /* only one input file allowed with -o */
        {                                        /* input and output files must have different names */
            if (!strcmp (argv[optind], output_file_name))
            {
                fprintf( stderr, "Input and output files must have different names.\n");
                usage();
                exit( 1 );
            }
            if (crypt_file( argv[optind], output_file_name) != 0)  /* encrypt file */
                exit( 1 );
            if ((delete_mode == DELETE_ALL_NORMAL) ||
                (delete_mode == DELETE_ALL_DOD))
                   delete( delete_mode, argv[optind]);   /* delete input file */
        }
        else                                     /* more than one input file with -o option */
        {
            fprintf( stderr, "Not just one input file with -o option.\n");
            usage();
            exit( 1 );
        }
    }
    else  /* multiple input files may be given with no -o option */
    {
        if (argc > optind)                       /* if there is at least one input file */
            while (optind < argc)                /* process them all */
            {                                    
                /* make the full path name of the input file */
                if (_fullpath( full_argv_name, argv[optind], 128 ) == NULL )
                {
                    fprintf( stderr, "Could not create full path name\n");
                    usage();
                    exit( 1 );
                }
                /* Get path components */
                _splitpath( full_argv_name, sDrive, sDir, sFname, sExt );
                /* The input file name may contain MSDOS wildcard
                   characters.  We now preallocate all file names.
                   We do this because we will be rewriting existing files
                   that match MSDOS patterns.  This prevents the MSDOS
                   next file function from becomming confused.  This is
                   done by chaining a series of structures that contain
                   the file name and a pointer to the next structure.
                   At the end, malloc()ed memory is free()ed.
                */
                new_files = zero_files;          /* initialize base structure */
                fnPointer = &new_files;          /* initialize current pointer */
                while ( (next_file_name = nextfile( full_argv_name )) != NULL )
                {                                /* get a new structure */
                    if ((fnPointer->next = (struct fnames *) malloc( sizeof(struct fnames) )) == NULL)
                    {
                        fprintf(stderr, "malloc failure\n");
                        usage();
                        exit( 1 );
                    }
                    strcpy( fnPointer->name, next_file_name ); /* fill in file name */
                    fnPointer = fnPointer->next;               /* update pointer */
                    *fnPointer = zero_files;                   /* initialize new structure */
                }
                /* process all files names */
                fnPointer = &new_files;          /* reset base pointer */
                while (fnPointer->next != 0)     /* process all names */
                {
                    next_file_name = fnPointer->name;      /* get new file name */
                    fnPointer = fnPointer->next;           /* get next pointer */
                    /* form full name and initialize temporary file name */
                    sprintf( full_file_name, "%s%s%s", sDrive, sDir, next_file_name);
                    cPointer = tempfile( full_file_name );
                    if (cPointer == NULL)
                    {                                     
                        fprintf(stderr, "Could not identify a temporary file\n");
                        usage();
                        exit( 1 );
                    }
                    strcpy(temporary, cPointer);
                    /* rename next file to temporary */
                    if ( rename( full_file_name, temporary ) != 0 )
                    {
                        fprintf( stderr, "Could not create temporary file\n");
                        usage();
                        exit( 1 );
                    }
                    /* encrypt back to original file name */
                    if ( crypt_file( temporary, full_file_name ) != 0 )
                    {
                        /* Encryption failed.  Restore as much as possible */
                        delete( DELETE_NORMAL, full_file_name );
                        rename( temporary, full_file_name );
                        exit( 1 );
                    }
                    /* required delete of temporary file */
                    delete( delete_mode, temporary );
                }
                /* free all allocated file names */
                if (new_files.next != (struct fnames *) 0)
                {
                    for (;;)
                    {
                        fnPointer = new_files.next;
                        new_files = *new_files.next;
                        free( fnPointer );
                        if (new_files.next == (struct fnames *) 0)
                            break;
                    }
                }
            optind++;  /* next command line input */
            }
    }

    /* Process commands from file if -f given */
    if (command_file_name[0])
    {
        if ((fPointer=fopen(command_file_name, "r")) != NULL)
        {
            while ( fgets(buffer, 512, fPointer) != NULL )
            {
                if( (cPointer = strchr( buffer, '\n' )) != NULL)
                    *cPointer = '\0';
                if( (cPointer = strchr( buffer, '\r' )) != NULL)
                    *cPointer = '\0';
                parseline( buffer );
            }
            fclose( fPointer );
        }
        else
        {
            fprintf( stderr, "Could not open command file %s\n", command_file_name );
            usage();
            exit( 1 );
        }
    }
    return;
}

void
parseline( char *line )
{
    int inquote = 0;
    int argc;
    char *argv[80],
      *p;

    p = line;
    argc = 1;
    argv[0] = "CRYPT.EXE";  /* just give some name */
    argv[1] = NULL;

    for (;;)
    {
        while (isspace(*p))
            p++;
        if (*p == '\'' || *p == '\"')
            inquote = *p++;
        if (*p == '\0')
            break;
        argv[argc++] = p++;
        argv[argc] = NULL;
        if (argc >= 80)
        {
            fprintf(stderr, "Error: too many arguments on line.\n");
            usage();
            exit( 1 );
        }
        if (inquote)
        {
            while ((*p != inquote) && (*p != '\0'))
                p++;
            if (*p == '\0')
                break;
            *p++ = '\0';
            inquote = 0;
        }
        else
        {
            while( !isspace(*p) && (*p != '\0'))
                p++;
            if (*p == '\0')
                break;
            *p++ = '\0';
        }
    }
    nextline( argc, argv );
    return;
}

void
delete( int mode, char *file_name )    /* Delete file according to given mode */
{
    struct _stat buf;
    int result;
    long file_size;
    long i;
    FILE *fPointer;

    result = _stat( file_name, &buf );
    if (result != 0)
    {
        fprintf( stderr, "Delete failure: Can not get size of file %s\n", file_name);
        usage();      
        exit( 1 );
    }
    file_size = buf.st_size;
    if ((fPointer = fopen( file_name, "r+" )) == NULL)
    {
        fprintf( stderr, "Delete failure: Can not open %s for read update\n", file_name);
        usage();
        exit( 1 );
    }

    if ((mode == DELETE_NORMAL) ||
        (mode == DELETE_ALL_NORMAL))
    {
        for (i = 0; i < buf.st_size; i++)        /* there may be faster routines */
            putc( overwrite, fPointer);
    }
    else if ((mode == DELETE_DOD) ||
             (mode == DELETE_ALL_DOD))
    {
        for (i = 0; i < buf.st_size; i++)
            putc( 1, fPointer);
        fflush( fPointer );
        fclose( fPointer );
        fPointer = fopen( file_name, "r+" );
        for (i = 0; i < buf.st_size; i++)
            putc( 0, fPointer);
        fflush( fPointer );
        fclose( fPointer );
        fPointer = fopen( file_name, "r+" );
        for (i = 0; i < buf.st_size; i++)
            putc( 1, fPointer);
        fflush( fPointer );
        fclose( fPointer );
        fPointer = fopen( file_name, "r+" );
        for (i = 0; i < buf.st_size; i++)
            putc( 0, fPointer);
        fflush( fPointer );
        fclose( fPointer );
        fPointer = fopen( file_name, "r+" );
        for (i = 0; i < buf.st_size; i++)
            putc( 1, fPointer);
        fflush( fPointer );
        fclose( fPointer );
        fPointer = fopen( file_name, "r+" );
        for (i = 0; i < buf.st_size; i++)
            putc( 0, fPointer);
        fflush( fPointer );
        fclose( fPointer );
        fPointer = fopen( file_name, "r+" );
        for (i = 0; i < buf.st_size; i++)
            putc( overwrite, fPointer);
    }
    fflush( fPointer );
    fclose( fPointer );
    remove( file_name );
    return;
}

int
give_help( int argc, char *argv[] )
{
    char **help;

    /* Give help in case it is asked for, then return 0 */
    if (argc == 2)
        if ( !strcmp(argv[1],"-?")     ||
             !strcmp(argv[1],"--help") ||
             !strcmp(argv[1],"--HELP") )
        {
            printf ( "NAME\n");
            printf ( "      %s - perform file encryption and decryption\n\n", prog );
            printf ( "SYNOPSIS\n");
            printf ( "      %s [-edcqQgG] [-k \"key\"] [-f file] [-# number] infile ...\n", prog );
            printf ( "      %s [-edcqQgG] [-k \"key\"] [-f file] [-# number] infile -o outfile\n\n", prog );
            for ( help=documentation; *help; help++ )
                printf( "%s\n", *help );
            printf( "\n" );
            for ( help=crypt_help(); *help; help++ )
                printf( "%s\n", *help );
            return 1;  /* help given */
        }
    return 0;  /* no help given */
}

void
usage( void )
{
    fprintf (stderr, "Usage: %s [-edcqQgG] [-k \"key\"] [-f file] [-# number] infile ...\n", prog);
    fprintf( stderr, "       %s [-edcqQgG] [-k \"key\"] [-f file] [-# number] infile -o outfile\n", prog);
    fprintf (stderr, "Help:  %s -?\n", prog);
    return;
}

void
copyright( void )
{
    printf("%s v1.00 Copyright 1995 Willis E. Howard, III.\n", prog);
    printf("The source code may contain additional copyright notices.\n");
    printf("email: WEHoward@aol.com\n");
    return;
}
