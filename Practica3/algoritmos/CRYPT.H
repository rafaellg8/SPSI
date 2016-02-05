/* crypt.h */

/* file name pointer structure */
struct fnames
{
    struct fnames *next;
    char name[13];
} ;

/* Possible delete modes for an input file */
#define DELETE_ALL_NORMAL  1
#define DELETE_NORMAL      2
#define DELETE_ALL_DOD     3
#define DELETE_DOD         4

/* Pipe commitments */
#define PIPE_UNUSED 0
#define PIPE_FOR_COMMAND 1
#define PIPE_USED 4

/* key types for communication with crypt_key() */
#define KEY_FILE 1
#define KEY_IMMEDIATE 2

/* Select encryption / decryption */
#define ENCRYPTION_SELECT 0
#define DECRYPTION_SELECT 1

/* functions in the main crypt.c module */
void parseline ( char * );
void nextline( int, char ** );
void delete( int, char * );
int give_help( int, char ** );
void usage( void );
void copyright( void );

/* functions in the specific encryption module */
char **crypt_help( void );
int crypt_key( int, char * );
int crypt_select( int );
int crypt_file( char *, char * );
void crypt_key_erase( void );
