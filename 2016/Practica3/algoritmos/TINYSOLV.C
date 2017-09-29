/* tinysolv.c */
/* Extended Euclidian and gcd functions from Schneier */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

#include <stdio.h>

/* under MSDOS, NMAKE /F TINYSOLV.MAK all clean */

/* Solve the decryption for tinyRSA.

   This demonstrates that the key to RSA is very large numbers.
   tinyRSA is limited to integers for the keys, and only processes
   characters.  This routine solves the private key only with
   knowledge of the public keys.  Give the short key first and
   the long key second on the command line.  For example,
   "TINYSOLV 45 5251" will report the private key as "2949 5251".
   The two primes used to generate these keys are 191 and 283.
   This is a brute force attack that searches all possible
   initial prime number pairs until a match is found.
*/

/* External function to test primeness of integers */
int isprime (unsigned int);

/* Report the greatest common divisor of x and y */

long
gcd_l (long x, long y)
{
    long g;

    if (x < 0)
        x = -x;
    if (y < 0)
        y = -y;
    g = y;
    while (x > 0)
    {
        g = x;
        x = y % x;
        y = g;
    }
    return g;
}

/* Perform extended Euclidian evaluation of u and v */

static void
update (long *un, long *vn, long q)
{
    long tn;

    tn = *un - *vn * q;
    *un = *vn;
    *vn = tn;
}

long
eeuclid_l (long u, long v, long *u1_out, long *u2_out)
{
    long u1 = 1;
    long u3 = u;
    long v1 = 0;
    long v3 = v;
    long q;

    while (v3 > 0)
    {
        q = u3 / v3;
        update (&u1, &v1, q);
        update (&u3, &v3, q);
    }
    *u1_out = u1;
    *u2_out = (u3 - u1 * u) / v;
    return u3;
}

/* Return the private key given public keys e and n. */
/* Return zero if private key could not be found. */
/* This is a brute force attack that tries all possible combinations. */
/* For only integers, the number of combinations is very small. */

unsigned int
solve (unsigned int e, unsigned int n)
{
    unsigned int p;
    unsigned int q;
    unsigned int l;
    long u1;
    long u2;

    for (p = 1; p < n; p++)
    {
        if (isprime (p))
        {
            q = n / p;
            if ((n == q * p) && isprime (q))
            {
                l = (q - 1) * (p - 1);
                if (gcd_l ((long) e, (long) l) == 1)
                {
                    if (eeuclid_l ((long) e, (long) l, &u1, &u2) == 1)
                    {
                        while (u1 < 0)
                            u1 += (long) l;
                        return (unsigned int) u1;
                    }
                }
            }
        }
    }
    return 0;
}

/* Main routine to call the solve function and report results */

main (int argc, char **argv)
{
    unsigned int x;
    unsigned int y;
    unsigned int z;

    /* display copyright if asked for */
    if ((argc == 2) && !strcmp(argv[1],"-c"))
    {
        printf("tinysolv v1.00 Copyright 1995 Willis E. Howard, III.\n");
        printf("email: WEHoward@aol.com\n");
        exit(0);
    }

    /* display help if asked for */
    if ((argc == 2) && !strcmp(argv[1],"-?"))
    {
        printf ("tinysolv:  solve the decryption keys for tinyRSA\n");
        printf ("usage:     tinysolv key1 key2\n");
        printf ("copyright: tinysolv -c\n");
        printf ("help:      tinysolv -?\n\n");
        printf ("DESCRIPTION\n\n");
        printf ("This demonstrates that the key to RSA is very large numbers.\n");
        printf ("tinyRSA is limited to integers for the keys, and only processes\n");
        printf ("characters.  This routine solves the private key only with\n");
        printf ("knowledge of the public keys.  Give the short key first and\n");
        printf ("the long key second on the command line.  For example,\n");
        printf ("TINYSOLV 45 5251 will report the private key as 2949 5251.\n");
        printf ("This is a brute force attack that searches all possible\n");
        printf ("initial prime number pairs until a match is found.\n");
        exit(0);
    }

    if (argc != 3)
    {
        printf ("error: Wrong number of arguments.\n");
        printf ("usage: tinysolv key1 key2\n");
        printf ("help:  tinysolv -?\n");
        exit (1);
    }
    sscanf (argv[1], "%u", &x);
    sscanf (argv[2], "%u", &y);
    z = solve (x, y);
    if (z)
        printf ("tinyRSA private decryption key for %u %u is %u %u\n", x, y, z, y);
    else
        printf ("No solution for %u %u\n", x, y);
    exit (0);
}
