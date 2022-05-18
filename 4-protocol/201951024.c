/*
 *    Anirudh Mitra 201951024
 *    CS364: Introduction to Cryptography and Network Security Laboratory
 *    Lab Assignment-4
 *    Implementation of Protocol in C
 */

/*
    Steps:
    1. select point on the curve, alpha. [output]
    2. take input alice's and bob's private keys, na and nb. [input]
    3. compute shared public key, sk(x1, y1) = na * nb * alpha. [output]
        nb * alpha means add alpha to itself na times. so we'll use elAdd() function to do that.
    4. alice and bob compute keys Ka and Kb. print Ka & Kb 32 bytes (space separated). [output]
        Ka = SHA-256(x1 || y1)
        Kb = SHA-256(x2 || y2)
*/

/* ----- HEADERS ----- */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

typedef uint8_t byte;
typedef uint32_t word;

/* ----- VARIABLES ----- */
int P = 101; // prime number
int a = 25;
int b = 31;
// TODO: change to random
int alpha[2] = {0, 43}; // point on the curve
// TODO: change to input
int na = 2, nb = 3; // private keys
int *SK;            // shared public key; x1 = SK[0], y1 = SK[1]
word state[8];
byte data[63];
word l;
uint64_t bl;
word hash[32];
word Ka[32], Kb[32];

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

// initialize array of round constants
const word k[64] =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/* ----- function declarations ----- */
word _rotr(word x, int n);
word _rotl(word x, int n);
word _sigma0(word x);
word _sigma1(word x);
word _epilogue0(word x);
word _epilogue1(word x);
word _ch(word x, word y, word z);
word _maj(word x, word y, word z);
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

/* ----- FUNCTION DECLARATIONS ----- */
void selectPoint();
int *elAdd(int[], int[]);
int addInv(int);
int multInv(int);
int *elMult(int, int[]);

void init();
void transform();
void add(byte[], uint32_t);
void finish();

/* ----- MAIN FUNCTION ----- */
int main()
{
    // 1. select point on the curve, alpha.[output]
    selectPoint();

    // 2. take input alice's and bob's private keys, na and nb. [input]

    // printf("\nEnter Alice's private key [1, 100]: ");
    // scanf("%d", &na);
    // printf("\nEnter Bob's private key [1, 100]: ");
    // scanf("%d", &nb);

    // 3. compute shared public key, sk(x1, y1) = na * nb * alpha. [output]
    SK = elMult(na * nb, alpha);
    printf("\nAlice's and Bob's shared public key: (%d, %d)\n", SK[0], SK[1]);

    // 4. alice and bob compute keys Ka and Kb. print Ka & Kb 32 bytes (space separated). [output] Ka = SHA-256(x1 || y1), Kb = SHA-256(x2 || y2)

    uint64_t xa = SK[0];
    xa = xa << 32 | SK[1];

    printf("\n%ld ", xa);

    // printf("\n%ld ", xa);
    byte xa_bytes[8];

    // break xa into 8 bytes
    for (int i = 0; i < 8; i++)
    {
        sprintf(xa_bytes, "%lx", xa);
        printf("%d", xa_bytes[i]);
    }

    init();
    add(xa_bytes, 8);
    finish(hash);

    // print hash
    for (int i = 0; i < 32; i++)
    {
        printf("%x ", hash[i]);
    }
}

/* ----- FUNCTION DEFINITIONS ----- */
void _transform()
{
    int i, j;
    word temp[64];
    for (i = 0, j = 0; i < 16; i++, j += 4)
    {
        temp[i] = data[j] << 24 | data[j + 1] << 16 | data[j + 2] << 8 | data[j + 3];
    }
    for (i = 16; i < 64; i++)
    {
        temp[i] = _sigma1(temp[i - 2]) + temp[i - 7] + _sigma0(temp[i - 15]) + temp[i - 16];
    }

    word a = state[0];
    word b = state[1];
    word c = state[2];
    word d = state[3];
    word e = state[4];
    word f = state[5];
    word g = state[6];
    word h = state[7];

    for (i = 0; i < 64; i++)
    {
        word tx = h + k[i] + temp[i] + _epilogue1(e) + _ch(e, f, g);
        word ty = _maj(a, b, c) + _epilogue0(a);

        h = g;
        g = f;
        f = e;
        e = d + tx;
        d = c;
        c = b;
        b = a;
        a = tx + ty;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// update function
void add(byte text[], uint32_t text_len)
{
    int i;
    for (i = 0; i < text_len; i++)
    {
        data[l] = text[i];
        l++;

        if (l == 64)
        {
            _transform();
            l = 0;
            bl += 512;
        }
    }
}

void finish(word hash[32])
{
    data[l] = 0x80;
    word i = l;

    if (l < 56)
    {
        i++;
        while (i < 56)
        {
            data[i++] = 0x00;
        }
    }
    else
    {
        i++;
        while (i < 64)
        {
            data[i++] = 0x00;
        }
        _transform();
        // fill data with zeros
        memset(data, 0, 56);
    }

    bl += l * 8;

    for (i = 0; i < 8; i++)
        data[63 - i] = bl >> (8 * i);

    _transform();

    for (i = 0; i < 4; i++)
    {
        hash[i] = (state[0] >> (24 - 8 * i)) & 0x000000ff;
        hash[i + 4] = (state[1] >> (24 - 8 * i)) & 0x000000ff;
        hash[i + 8] = (state[2] >> (24 - 8 * i)) & 0x000000ff;
        hash[i + 12] = (state[3] >> (24 - 8 * i)) & 0x000000ff;
        hash[i + 16] = (state[4] >> (24 - 8 * i)) & 0x000000ff;
        hash[i + 20] = (state[5] >> (24 - 8 * i)) & 0x000000ff;
        hash[i + 24] = (state[6] >> (24 - 8 * i)) & 0x000000ff;
        hash[i + 28] = (state[7] >> (24 - 8 * i)) & 0x000000ff;
    }
}

void init()
{
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;

    l = bl = 0;
}

/* ----- utility functions ----- */

// right circular shift
word _rotr(word x, int n)
{
    return (x >> n) | (x << (32 - n));
}
// left circular shift
word _rotl(word x, int n)
{
    return (x << n) | (x >> (32 - n));
}
// sigma 0
word _sigma0(word x)
{
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3);
}
// sigma 1
word _sigma1(word x)
{
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10);
}
// epilogue 0
word _epilogue0(word x)
{
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22);
}
// epilogue 1
word _epilogue1(word x)
{
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25);
}
// ch
word _ch(word x, word y, word z)
{
    return (x & y) ^ (~x & z);
}
// maj
word _maj(word x, word y, word z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

// function for calculating n * p using elAdd() function
int *elMult(int n, int p[])
{
    int *q = (int *)malloc(2 * sizeof(int));
    q = p;
    for (int i = 1; i < n; i++)
        q = elAdd(p, q);

    return q;
}

// function for adding two points on the curve
int *elAdd(int p[], int q[])
{
    int m;
    int theta[2] = {0, 1};
    int *sk = (int *)malloc(2 * sizeof(int));

    // case 1
    if ((p[0] != q[0]) && (p[1] != q[1]))
    {
        m = (q[1] + addInv(p[1])) * multInv(q[0] + addInv(p[0])) % P;

        sk[0] = (m * m + addInv(p[0]) + addInv(q[0])) % P;
        sk[1] = (p[1] + m * (sk[0] + addInv(p[0]))) % P;
        sk[1] = addInv(sk[1]);
    }
    // case 3
    else if ((p[0] == q[0]) && (p[1] == q[1]))
    {
        m = (3 * p[0] * p[0] + a) * multInv(2 * p[1]) % P;

        sk[0] = (m * m + addInv(2 * p[0])) % P;
        sk[1] = (p[1] + m * (sk[0] + addInv(p[0]))) % P;
        sk[1] = addInv(sk[1]);
    }
    // case 2
    else if ((p[0] == q[0]) && (p[1] == -1 * q[1]))
    {
        sk[0] = theta[0];
        sk[1] = theta[1];
    }
    // printf("\nSK: (%d, %d)\n", sk[0], sk[1]);
    return sk;
}

// function for finding additive inverse modulo P
int addInv(int x)
{
    return (P - x);
}

// function for finding multiplicative inverse modulo P using extended euclidean algorithm
int multInv(int a)
{
    for (int i = 1; i < P; i++)
        if (((a % P) * (i % P)) % P == 1)
            return i;
}

void selectPoint()
{
    // EL: y^2 = (x^3 + ax + b) mod p => y^2 = (x^3 + 25x + 31) mod 101
    int points[2][101] = {};
    int no_of_points = 0;

    // 1.1 find all points on the curve
    for (int x = 0; x < P; x++)
        for (int y = 0; y < P; y++)
        {
            int g = (x * x * x + 25 * x + 31) % P;
            if ((y * y - g) % P == 0)
            {
                // printf("(%d, %d)\n", x, y);
                points[0][no_of_points] = x;
                points[1][no_of_points] = y;

                no_of_points++;
            }
        }

    // 1.2 select random point from the list
    // srand(time(0));
    // int alphaIndex = rand() % noOfPoints;
    // alpha[0] = points[0][alphaIndex];
    // alpha[1] = points[1][alphaIndex];

    // printf("alpha: (%d, %d)\n", alpha[0], alpha[1]);
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
/* ----- ARCHIVE ----- */
/*
{
    print all multiplicative inverses modulo N
        printf("Multiplicative Inverses modulo\n");
    for (int i = 0; i < 2; i++)
    {
        int pp = multInv(p[i]);
        printf("p[%d]: %d\n", i, pp);
        int qq = multInv(q[i]);
        printf("q[%d]: %d\n", i, qq);
    }
    printf("p[0]: %d\n", multInv(p[0]));
    printf("p[1]: %d\n", multInv(p[1]));
    printf("q[0]: %d\n", multInv(q[0]));
    printf("q[1]: %d\n", multInv(q[1]));
}
*/
/*

*/
/*

*/