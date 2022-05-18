// SHA-256 implementation in c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t byte;
typedef uint32_t word;

/* ----- variables ----- */
word state[8];
byte data[63];
word l;
uint64_t bl;
word hash[32];

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

void init();
void transform();
void add(byte[], uint32_t);
void finish();

void main()
{
    byte text[] = {"abc"};
    init();
    add(text, 3);
    finish();

    // print hash
    for (int i = 0; i < 32; i++)
    {
        printf("%x", hash[i]);
    }
}

/* ----- function definitions ----- */
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

void finish()
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
