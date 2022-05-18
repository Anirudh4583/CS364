//  Anirudh Mitra 201951024
// square and multiply algorithm implementation in c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// function to square and multiply
// base x, exponent n, modulus p
// x^n mod p
int square_and_multiply(int x, int n, int p)
{
    int n_binary[32];
    int i = 0;
    while (n > 0)
    {
        if (n % 2 == 1)
            n_binary[i] = 1;
        else
            n_binary[i] = 0;

        n = n / 2;
        i++;
    }

    i = i - 1;
    int result = 1;

    while (i > 0)
    {
        if (n_binary[i] == 1)
            result = (result * x) % p;

        result = (result * result) % p;

        i--;
    }

    return result;
}

int main()
{
    // int x, n, p;

    // printf("Enter the values: ");
    // scanf("%d %d %d", &x, &n, &p);

    srand(time(NULL));
    // generate random number n1 and n2
    int n1 = 1 + rand() % 100;
    int n2 = 1 + rand() % 100;

    int p = 131;
    int g = 2;

    int ans = square_and_multiply(g, n1 * n2, p);

    printf("%d", ans);
    return 0;
}

/*
pseudocode:

def ModExp(x,e,N):
r"""
Calculates x^e mod N using square and multiply.
INPUT:
x - an integer.
e - a nonnegative integer.
N - a positive integer modulus.
OUTPUT:
y - x^e mod N
"""
e_bits = e.bits()
e_bitlen = len(e_bits)
y = 1
for j in xrange(e_bitlen):
y = y^2 % N
if (1 == e_bits[e_bitlen-1-j]):
y = x*y % N
return y
 */