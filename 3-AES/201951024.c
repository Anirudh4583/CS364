/*
 *    Anirudh Mitra 201951024
 *    CS364: Introduction to Cryptography and Network Security Laboratory
 *    Lab Assignment-3
 *    Implementation of Advanced Encryption Standard (AES-128) Algorithm in C
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef uint8_t byte;
typedef uint32_t word;

// AES S-box
byte Sbox[16][16] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

//  variables

// 128 bit message/plaintext; 16 bytes; 8 bit each
byte Message[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

// 0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef 0xfe 0xdc 0xba 0x98 0x76 0x54 0x32 0x10

// 128 bit key; 16 bytes
byte Key[16] = {
    0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98};
// 0x0f 0x15 0x71 0xc9 0x47 0xd9 0xe8 0x59 0x0c 0xb7 0xad 0xd6 0xaf 0x7f 0x67 0x98

// word array for the key; 44 words; 4 bytes each; 176 bytes
word W[44] = {};

// round keys; 1 4-word round key for initial AddRoundKey and 10 round keys for each round
byte roundKeys[11][4][4] = {};

byte roundMessage[4][4];

// function declarations
void compress();
void keyExpansion();
word subWord(word);
word rotWord(word);
void createRoundKeys();
void createMessageMatrix();
void AddRoundKey(int);
void printRoundMessage(); // utility function for printing the roundMessage
void roundFunction();     // function for performing the roundFunction
byte subBytes(byte x);    // function for performing the subBytes operation
byte xf(byte);
void mixColumn(int i);
void roundFunction10(); // function for performing the round Function for 10th round

// main function
int main()
{
    // take message and key input
    printf("Enter the message: ");
    for (int i = 0; i < 16; i++)
    {
        scanf("%4hhx", &Message[i]);
    }

    printf("Enter the key: ");
    for (int i = 0; i < 16; i++)
    {
        scanf("%4hhx", &Key[i]);
    }

    compress();
}

// compression function that takes in 128-bit plaintext and 128-bit key and returns 128 bit ciphertext
void compress()
{
    keyExpansion();
    // print w
    // for (int i = 0; i < 44; i++)
    // {
    //     printf("w[%d] %x \n", i, W[i]);
    // }

    // create round keys in form of 4x4 matrix
    createRoundKeys();

    // print round keys
    for (int i = 0; i < 11; i++)
    {
        printf("round key %d \n", i);
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                printf("%x ", roundKeys[i][j][k]);
            }
            printf("\n");
        }
        printf("\n");
    }

    // turn message into 4x4 matrix
    createMessageMatrix();

    // add round key
    AddRoundKey(0);

    //  1-9 rounds
    for (int i = 1; i < 10; i++)
    {
        // print round message
        printf("round %d \n", i);
        printRoundMessage();

        // perform round function
        roundFunction();

        // add round key
        AddRoundKey(i);
    }

    // 10th round
    roundFunction10();
    AddRoundKey(10);

    // print round message
    printRoundMessage();
}

void roundFunction10()
{
    // 1. subBytes
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            roundMessage[i][j] = subBytes(roundMessage[i][j]);
        }
    }
    // 2. shiftRows
    for (int i = 1; i < 4; i++)
    {
        for (int j = 0; j < 4 - i; j++)
        {
            byte temp = roundMessage[i][j];
            roundMessage[i][j] = roundMessage[i][j + i];
            roundMessage[i][j + i] = temp;
        }
    }
}

void roundFunction()
{
    // 1. subBytes
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            roundMessage[i][j] = subBytes(roundMessage[i][j]);
        }
    }
    // 2. shiftRows
    for (int i = 1; i < 4; i++)
    {
        for (int j = 0; j < 4 - i; j++)
        {
            byte temp = roundMessage[i][j];
            roundMessage[i][j] = roundMessage[i][j + i];
            roundMessage[i][j + i] = temp;
        }
    }
    // 3. mixColumns
    for (int i = 0; i < 4; i++)
        mixColumn(i);
}

void mixColumn(int i)
{
    roundMessage[0][i] = xf(roundMessage[0][i]) ^ xf(roundMessage[1][i]) ^ roundMessage[1][i] ^ roundMessage[2][i] ^ roundMessage[3][i];
    roundMessage[1][i] = roundMessage[0][i] ^ xf(roundMessage[1][i]) ^ xf(roundMessage[2][i]) ^ roundMessage[2][i] ^ roundMessage[3][i];
    roundMessage[2][i] = roundMessage[0][i] ^ roundMessage[1][i] ^ xf(roundMessage[2][i]) ^ xf(roundMessage[3][i]) ^ roundMessage[3][i];
    roundMessage[3][i] = xf(roundMessage[0][i]) ^ roundMessage[0][i] ^ roundMessage[1][i] ^ roundMessage[2][i] ^ xf(roundMessage[3][i]);
}

byte xf(byte temp)
{
    byte g;
    if ((temp >> 7) == 0)
        g = temp << 1;
    else
        g = (temp << 1) ^ 0x1b;

    return g;
}

byte subBytes(byte x)
{
    byte X = x & 15;
    byte Y = (x >> 4) & 15;

    // printf("%d %d", X, Y);

    byte ans = Sbox[Y][X];

    return ans;
}

void AddRoundKey(int x)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            roundMessage[i][j] = roundMessage[i][j] ^ roundKeys[x][i][j];
}

// create round keys from expanded key
void createRoundKeys()
{
    // concatenate 4 W's together to form one round key
    for (int i = 0; i < 11; i++)
        for (int j = 0; j < 4; j++)
            for (int k = 0; k < 4; k++)
                roundKeys[i][j][k] = W[i * 4 + k] >> (24 - 8 * j);
}

void createMessageMatrix()
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            roundMessage[i][j] = Message[4 * j + i];
}

void printRoundMessage()
{
    // print roundMessage
    for (int i = 0; i < 4; i++)
    {
        printf("\n");
        for (int j = 0; j < 4; j++)
            printf("%x ", roundMessage[i][j]);
    }
}

// key expansion function
void keyExpansion()
{
    const word Rcon[11] = {
        0x00, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

    // copy the key into the first 4 words of the key schedule array
    // w0 to w3
    for (int i = 0; i < 4; i++)
    {
        W[i] = (Key[4 * i] << 24) | (Key[4 * i + 1] << 16) | (Key[4 * i + 2] << 8) | Key[4 * i + 3];
    }

    // w3 to w43
    word temp;
    for (int i = 4; i < 44; i++)
    {
        temp = W[i - 1];
        if (i % 4 == 0)
        {
            temp = subWord(rotWord(temp)) ^ Rcon[i / 4]; // Rcon[i/4 - 1]
            // printf("temp: %x \n", temp);
        }
        W[i] = W[i - 4] ^ temp;
    }
}

// rotWord function that performs one-byte circular left shift on a word
// i/p: [B0, B1, B2, B3]; o/p: [B1, B2, B3, B0]
word rotWord(word temp)
{
    word ans = ((temp & 0xFF) << 8) | (((temp >> 8) & 0xFF) << 16) | (((temp >> 16) & 0xFF) << 24) | ((temp >> 24) & 0xFF);

    printf("\nrotWord: %x \n", ans);

    return ans;
}

// subWord function that performs the substitution of a word with the S-box
word subWord(word temp)
{
    // sbox is a 2d array of 16 x 16
    // apply sbox to each byte of the word

    // get the first byte
    byte b0 = (temp >> 24) & 0xFF;
    // get the second byte
    byte b1 = (temp >> 16) & 0xFF;
    // get the third byte
    byte b2 = (temp >> 8) & 0xFF;
    // get the fourth byte
    byte b3 = temp & 0xFF;

    word ans = (Sbox[(b0 >> 4) & 15][b0 & 15] << 24) | (Sbox[(b1 >> 4) & 15][b1 & 15] << 16) | (Sbox[(b2 >> 4) & 15][b2 & 15] << 8) | Sbox[(b3 >> 4) & 15][b3 & 15];

    printf("\n\nsubWord: %x \n\n", ans);

    // apply sbox to each byte
    return ans;
}

/*

!###########! ARCHIVE !###########!

void keyExpansion()
{
    const char Rcon[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

    // copy entire key into w[0] to w[3]
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            W[i][j] = Key[4 * i + j];

    char temp[4];

    // w[4] to w[43]
    for (int i = 4; i < 44; i++)
    {
        for (int j = 0; j < 4; j++)
            temp[j] = W[i - 1][j];

        if (i % 4 == 0)
            for (int j = 0; j < 4; j++)
                temp[j] = subWord(rotWord(temp)) ^ Rcon[i / 4];

        for (int j = 0; j < 4; j++)
            W[i][j] = W[i - 4][j] ^ temp[j];
    }
}

// rotWord function that performs one-byte circular left shift on a word
// i/p: [B0, B1, B2, B3]; o/p: [B1, B2, B3, B0]
char *rotWord(char temp[])
{
    char temp2[4];
    for (int i = 0; i < 4; i++)
        temp2[i] = temp[(i + 1) % 4];
    for (int i = 0; i < 4; i++)
        temp[i] = temp2[i];

    return temp;
}

*/