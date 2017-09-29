/* cdrom.h */

#define CD_COMPRESS

/* raw CD I/O */
unsigned char * CD_read_sector( char *, unsigned long );
unsigned char * CD_read_ID( char );
unsigned long get_CD_sector( void );

/* buffered CD I/O */
int CD_offset( int );
unsigned int CD_char( void );
int get_CD_offset( void );

