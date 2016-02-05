/* hex.c */
/* Test hex digits and convert hex to integer */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

#include "hex.h"

int
ishex (unsigned char c)
{
    if (c >= '0' || c <= '9')
        return 1;
    if (c >= 'a' || c <= 'f')
        return 1;
    if (c >= 'A' || c <= 'F')
        return 1;
    return 0;
}

int 
hextoint (unsigned char c)
{
    if (!ishex (c))
        return -1;

    switch (c)
    {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return (c - '0');
        break;
    case 'a':
    case 'A':
        return 10;
        break;
    case 'b':
    case 'B':
        return 11;
        break;
    case 'c':
    case 'C':
        return 12;
        break;
    case 'd':
    case 'D':
        return 13;
        break;
    case 'e':
    case 'E':
        return 14;
        break;
    case 'f':
    case 'F':
        return 15;
        break;
    default:
        return -1;
        break;
    }

    return -1;
}
