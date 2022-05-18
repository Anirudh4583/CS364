/*
 *    Anirudh Mitra 201951024
 *    CS364: Introduction to Cryptography and Network Security Laboratory
 *    Lab assignment-3
 *    Implementation of Advanced Encryption Standard (AES) Algorithm in C
 */

#include <stdio.h>

char xf(char);

int main()
{
    char s[4][1] = {{0x87},
                    {0x6E},
                    {0x46},
                    {0xA6}};

    char _s[4][1] = {};

    _s[0][0] = xf(s[0][0]) ^ xf(s[1][0]) ^ s[1][0] ^ s[2][0] ^ s[3][0];
    _s[1][0] = s[0][0] ^ xf(s[1][0]) ^ xf(s[2][0]) ^ s[2][0] ^ s[3][0];
    _s[2][0] = s[0][0] ^ s[1][0] ^ xf(s[2][0]) ^ xf(s[3][0]) ^ s[3][0];
    _s[3][0] = xf(s[0][0]) ^ s[0][0] ^ s[1][0] ^ s[2][0] ^ xf(s[3][0]);

    for (int i = 0; i < 4; i++)
    {
        printf("%x \n", _s[i][0]);
    }

    return 0;
}

char xf(char temp)
{
    char g;
    if ((temp >> 7) == 0)
        g = temp << 1;
    else
        g = (temp << 1) ^ 0x1b;

    return g;
}