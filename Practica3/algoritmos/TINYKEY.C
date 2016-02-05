/* tinykey.c */
/* Produce public and private keys for tinyRSA */
/* Copyright 1995 Willis E. Howard, III */
/* Willis E. Howard, III  email: WEHoward@aol.com  mail: POB 1473 Elkhart, IN  46515 */

#include <stdio.h>
#include <string.h>
int isprime (unsigned int);

/* under MSDOS, NMAKE /F TINYKEY.MAK all clean */

/* Return greatest common denominator (long) */

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
        if (x < 0)
            x += y;
        y = g;
    }
    return g;
}

/* return modular exponentiation (long) */

long
modexp_l (long a, long x, long n)                /* a to the x mod n */
{
    long r = 1;

    while (x > 0)
    {
        if (x & 1)                              /* is x odd? */
            r = (r * a) % n;
        a = (a * a) % n;
        x /= 2;
    }
    return r;
}

/* Return extended Euclidian computation (long) */

static void
update (long *un, long *vn, long q)
{
    long tn;

    tn = *un - *vn * q;
    *un = *vn;
    *vn = tn;
}

int
extended_euclidian (long u, long v, long *u1_out, long *u2_out)
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

/* Main routine to get primes and calculate keys */

main (int argc, char **argv)
{
    int i, j, k;
    long message, msg;
    long l, p, e, d;
    long u1out, u2out;

    /* display copyright if asked for */
    if ((argc == 2) && !strcmp(argv[1],"-c"))
    {
        printf("tinykey v1.00 Copyright 1995 Willis E. Howard, III.\n");
        printf("email: WEHoward@aol.com\n");
        exit(0);
    }

    /* provide help if asked for */
    if ((argc == 2) && !strcmp(argv[1],"-?"))
    {
        printf("tinykey:   compute public and private keys for tinyRSA\n");
        printf("usage:     tinykey [prime1 [prime2 [random]]]\n");
        printf("copyright: tinykey -c\n");
        printf("help:      tinykey -?\n\n");
        printf("DESCRIPTION\n\n");
        printf("The product of the prime numbers prime1 and prime2 must be\n");
        printf("less than 32K and larger than 255.  The random number must\n");
        printf("be less than (prime1 - 1)*(prime2 - 1).  If the input numbers\n");
        printf("are not prime, the next higher prime number will be used.\n");
        printf("If no command line parameters are given, you will be prompted\n");
        printf("for the numbers with appropriate ranges indicated.  The full\n");
        printf("range for encryption and decryption is tested.  Do not use\n");
        printf("the keys if the testing fails.  Rather, select alternative\n");
        printf("prime and/or random numbers.  The estimated input ranges may\n");
        printf("sometimes be too large, and smaller numbers may be required.\n");
        printf("Additional help is available from program tinyRSA.\n");
        exit(0);
    }

    if (argc == 1)
    {
        printf("tinykey:   compute public and private keys for tinyRSA\n");
        printf("usage:     tinykey [prime1 [prime2 [random]]]\n");
        printf("copyright: tinykey -c\n");
        printf("help:      tinykey -?\n\n");
        printf("Prompts are given for all prime and random numbers.\n\n");
    }

    /* Get the first prime number */
    if (argc >= 2)
        sscanf(argv[1], "%u", &i);
    else
    {
        printf ("Input a prime number less than 2048:  ");
        scanf ("%u", &i);
    }
    /* No error if the number is not prime, just get the next highest prime */
    for (k = i; (unsigned) k < 65534; k++)
        if (isprime (k))
            break;
    i = k;

    /* Get the second prime number.  If not prime, get the next highest one */ 
    if (argc >= 3)
        sscanf(argv[2], "%u", &j);
    else
    {
        k = (unsigned)32000 / i;
        printf ("Input a prime number less than %u", k);
        if ((256/i) > 2)
            printf (" but greater than %u", 256/i);
        printf(":  ");
        scanf ("%u", &j);
    }
    for (k = j; (unsigned)k < 65534; k++)
        if (isprime (k))
            break;
    j = k;

    /* These are the important numbers */
    l = (long) (i - 1) * (long) (j - 1);
    p = (long) i *(long) j;

    /* Get a random number that will be processed into the public key. */
    /* The estimated maximum may be too large if e must be incremented */
    /* too much before gcd(e,l) = 1. */
    if (argc >= 4)
        sscanf(argv[3], "%lu", &e);
    else
    {
        printf ("Input a random number less than %lu:  ", l);
        scanf ("%lu", &e);
    }

    /* Increment e until e and l are relatively prime. */
    /* Also insure that e and d are not equal. */
    d = 0;
    do
    {
        if (e == d)
            e++;
        while (gcd_l (e, l) != 1)
            e++;
        (void) extended_euclidian (e, l, &u1out, &u2out);
        d = u1out;
        while (d < 0)
            d += l;
    } while (e == d);

    /* check for error conditions */
    if (p & 0xffff8000)      /* no larger than 32K */
    {
        printf ("error: Prime numbers were too large\n");
        printf ("usage: tinykey [prime1 [prime2 [random]]]\n");
        printf ("help:  tinykey -?\n");
        exit (1);
    }
    if (p < 256)             /* no smaller than 256 */
    {
        printf ("error: Prime numbers were too small\n");
        printf ("usage: tinykey [prime1 [prime2 [random]]]\n");
        printf ("help:  tinykey -?\n");
        exit (1);
    }
    if (e > l)        /* e no smaller than l */
    {
        printf ("error: Random number was too large\n");
        printf ("usage: tinykey [prime1 [prime2 [random]]]\n");
        printf ("help:  tinykey -?\n");
        exit (1);
    }

    /* Report the keys */
    printf ("public encryption key: %lu %lu\n", e, p);
    printf ("private decryption key: %lu %lu\n", d, p);

    /* Test the full range of the keys */
    printf ("Testing ...");
    for (message = 0 ; message < p; message++)
    {
        msg = modexp_l (message, e, p);
        msg = modexp_l (msg, d, p);
        if (msg != message)
        {
            printf ("\b\b\bfailed at sequence = %lu.\nUse different parameters.\n", message);
            printf ("help:  tinykey -?\n");
            exit(1);
        }
    }
    printf("\b\b\bpassed.\n");
    exit(0);
}

