/*
 *    Anirudh Mitra 201951024
 *    CS364: Introduction to Cryptography and Network Security Laboratory
 *    Eliptic Curve Cryptography Algorithm in C
 */

#include <stdio.h>
#include <stdlib.h>

// variables
int N = 101; // prime number
int r[2];

// function declarations
int addInv(int);  // function for finding additive inverse modulo P
int multInv(int); // function for finding multiplicative inverse modulo P
void elAdd(int[], int[]);

int main()
{
    /*
    curve E: y2 = x3 + x + 6 mod 13
    a = 1, b = 6, n = 13
    */

    // for (int x = 0; x < N; x++)
    //     for (int y = 0; y < N; y++)
    //     {
    //         int g = (x * x * x + x + 6) % N;
    //         if ((y * y - g) % N == 0)
    //         {
    //             printf("(%d, %d)\n", x, y);
    //         }
    //     }

    int x1[2] = {0, 43}, x2[2] = {0, 43}; // r = {8, 3}
    elAdd(x1, x2);
    printf("(%d, %d)\n", r[0], r[1]);
    return 0;
}

void elAdd(int p[], int q[])
{
    int m;
    // int theta[2] = {};

    // print all multiplicative inverses modulo N
    // printf("Multiplicative Inverses modulo\n");
    // for (int i = 0; i < 2; i++)
    // {
    //     int pp = multInv(p[i]);
    //     printf("p[%d]: %d\n", i, pp);
    //     int qq = multInv(q[i]);
    //     printf("q[%d]: %d\n", i, qq);
    // }
    // printf("p[0]: %d\n", multInv(p[0]));
    // printf("p[1]: %d\n", multInv(p[1]));
    // printf("q[0]: %d\n", multInv(q[0]));
    // printf("q[1]: %d\n", multInv(q[1]));

    if ((p[0] != q[0]) && (p[1] != q[1]))
    {
        m = (q[1] + addInv(p[1])) * multInv(q[0] + addInv(p[0])) % N;

        r[0] = (m * m + addInv(p[0]) + addInv(q[0])) % N;
        r[1] = (p[1] + m * (r[0] + addInv(p[0]))) % N;
        r[1] = addInv(r[1]);
    }
    else if ((p[0] == q[0]) && (p[1] == q[1]))
    {
        m = (3 * p[0] * p[0] + 25) * multInv(2 * p[1]) % N;

        r[0] = (m * m + addInv(2 * p[0])) % N;
        r[1] = (p[1] + m * (r[0] + addInv(p[0]))) % N;
        r[1] = addInv(r[1]);
    }
    else if ((p[0] == q[0]) && (p[1] == -1 * q[1]))
    {
        // r[0] = theta[0]
        // r[1] = theta[1]
    }
}

// function for finding additive inverse modulo P
int addInv(int x)
{
    return (N - x);
}

// function for finding multiplicative inverse modulo P using extended euclidean algorithm
int multInv(int a)
{
    for (int i = 1; i < N; i++)
        if (((a % N) * (i % N)) % N == 1)
            return i;
}