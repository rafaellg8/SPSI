/* zblock.h */

#ifndef BLOCKSIZE

/* the absolute maximum for BLOCKSIZE is 4096 */
#define BLOCKSIZE 2048

struct zipblock 
{
    unsigned int count;                /* actual count */
    unsigned int max;                  /* maximum count */
    char buffer[BLOCKSIZE];            /* data */
}; 

struct zipheader
{
    unsigned count;
    unsigned max;
    union
    {     char buffer[4];
          int  number[2];
    };
};

int zipupblock( struct zipblock *, struct zipblock * );
int unzipblock( struct zipblock *, struct zipblock * );

#endif

