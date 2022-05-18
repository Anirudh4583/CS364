// Anirudh Mitra 201951024
// Lab assignment 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void encrypt();
void decrypt();
void decrypt_c(char[], int);

int main()
{
	encrypt();
	decrypt();
	return 0;
}

// searching function for k1
void search(char k1[5][5], char p1, char p2, int a[])
{
	//  iterate through the matrix rows
	for (int x = 0; x < 5; x++)
	{
		//  iterate through the matrix columns
		for (int y = 0; y < 5; y++)
		{

			if (k1[x][y] == p1)
			{
				a[0] = x;
				a[1] = y;
			}
			else if (k1[x][y] == p2)
			{
				a[2] = x;
				a[3] = y;
			}
		}
	}
}

// playfair encryption function; takes i/p plaaintext, lenght of plaintext & key matrix
void encrypt_pf(char P[], int p_len, char k1[5][5])
{
	int i, pos[4];
	// array pos will store positions of the plaintext characters in the key matrix
	// pos[0] = row of p1,
	// pos[1] = column of p1,
	// pos[2] = row of p2,
	// pos[3] = column of p2

	for (int i = 0; i < p_len; i += 2)
	{

		// search for every pair of letters in the plaintext
		// and replace them with their corresponding
		// letters in the key matrix
		search(k1, P[i], P[i + 1], pos);

		// if the letters are in the same row
		if (pos[0] == pos[2])
		{
			P[i] = k1[pos[0]][(pos[1] + 1) % 5];
			P[i + 1] = k1[pos[0]][(pos[3] + 1) % 5];
		}
		// if the letters are in the same column
		else if (pos[1] == pos[3])
		{
			P[i] = k1[(pos[0] + 1) % 5][pos[1]];
			P[i + 1] = k1[(pos[2] + 1) % 5][pos[1]];
		}
		// none
		else
		{
			P[i] = k1[pos[0]][pos[3]];
			P[i + 1] = k1[pos[2]][pos[1]];
		}
	}
}

// caesar cipher encryption function; takes i/p plaintext & key
void encrypt_c(char P[], int k2)
{
	for (int i = 0; P[i] != '\0'; i++)
	{
		P[i] += k2;
		if (P[i] > 'z')
		{
			P[i] -= 'z' - 'a' + 1;
		}
	}
}

// affine cipher encryption function; takes i/p: plaintext & keys
void encrypt_a(char P[], int k3, int k4)
{
	for (int i = 0; P[i] != '\0'; i++)
	{
		P[i] = ((k3 * (P[i] - 'a')) + k4) % 26 + 'a';
	}
}

// Encryption
void encrypt()
{
	// step 1: plaintext
	char plaintext[100];

	// 	take plaintext as input
	printf("Enter plaintext: ");
	gets(plaintext);

	// 	adjust length according to playfair rules
	int p_len = strlen(plaintext);
	if (strlen(plaintext) % 2 != 0)
	{
		plaintext[p_len] = 'x';
		plaintext[p_len + 1] = '\0';
	}

	// 	convert J to I
	for (int i = 0; plaintext[i] != '\0'; i++)
	{
		if (plaintext[i] == 'j')
		{
			plaintext[i] = 'i';
		}
	}
	// 	text obtained is del
	char del[100];
	strcpy(del, plaintext);

	printf("\n delta: %s\n", del);

	// step 2 : key
	char key[100], k1[5][5];
	// print k1

	// take key as input
	printf("Enter key: ");
	gets(key);

	// convert J to I
	for (int i = 0; key[i] != '\0'; i++)
	{
		if (key[i] == 'j')
		{
			key[i] = 'i';
		}
	}

	// create 5*5 playfair matrix which is key k1
	int k_len = strlen(key);

	// taking a hash for storing count of each letter
	int *hash = (int *)calloc(26, sizeof(int));
	for (int i = 0; key[i] != '\0'; i++)
	{
		// make value of each letter as 2 so that we can create the matrix with only unique letters using 0 and 1
		hash[key[i] - 'a'] = 2;
	}

	// fill the matrix with letters in the key
	int x = 0, y = 0;
	for (int i = 0; i < k_len; i++)
	{
		if (hash[key[i] - 'a'] == 2)
		{
			k1[x][y] = key[i];
			hash[key[i] - 'a'] = 1;
			// increment column
			y++;
			if (y == 5)
			{
				// if column is full, increment row and reset column
				x++;
				y = 0;
			}
		}
	}

	// fill the matrix with remaining letters
	for (int i = 0; i < 26; i++)
	{
		if (hash[i] == 0 && (char)(i + 'a') != 'j')
		{
			k1[x][y] = 'a' + i; // error getting ascii
			hash[i] = 1;
			// increment column
			y++;
			if (y == 5)
			{
				// if column is full, increment row and reset column
				x++;
				y = 0;
			}
		}
	}

	// print k1
	printf("\n k1: \n ");
	for (int i = 0; i < 5; i++)
	{
		for (int j = 0; j < 5; j++)
		{
			printf("%c ", k1[i][j]);
		}
		printf("\n ");
	}

	// encrypt del using playfair cipher with key k1 -> c1
	encrypt_pf(del, p_len, k1);

	char c1[100];
	strcpy(c1, del);
	printf("\n cipher text, c1: %s\n", c1);

	// encrypt c1 using caesar cipher with key k2=3 -> c2
	int k2 = 3;

	encrypt_c(c1, k2);
	char c2[100];
	strcpy(c2, c1);

	// print c2
	printf("\n cipher text, c2: %s\n", c2);

	// encrypt c2 using affine cipher with key k3=(7, 5) -> c3
	int k3 = 17, k4 = 20;
	encrypt_a(c2, k3, k4);

	char c3[100];
	strcpy(c3, c2);

	// print c3
	printf("\n cipher text, c3: %s\n", c3);
}

// affine cipher decryption function; takes i/p: ciphertext & keys
void decrypt_a(char C[], int k3, int k4)
{
	// inverse of k3
	int inv = 0;
	for (int i = 0; i < 26; i++)
	{
		if ((k3 * i) % 26 == 1)
		{
			inv = i;
		}
	}

	// decrypt C using inv and k4
	for (int i = 0; C[i] != '\0'; i++)
	{
		C[i] = ((inv * (C[i] - 'a' - k4) % 26) % 26 + 'a');
	}
}

// caesar cipher decryption function; takes i/p: ciphertext & key
void decrypt_c(char C[], int k2)
{
	for (int i = 0; C[i] != '\0'; i++)
	{
		C[i] -= k2;
		if (C[i] < 'a')
		{
			C[i] += 'z' - 'a' + 1;
		}
	}
}

// playfair cipher decryption function
void decrypt_pf(char C[], int c_len, char k1[5][5])
{
	int i, pos[4];
	// array pos will store positions of the plaintext characters in the key matrix
	// pos[0] = row of p1,
	// pos[1] = column of p1,
	// pos[2] = row of p2,
	// pos[3] = column of p2

	for (int i = 0; i < c_len; i += 2)
	{
		// search for every pair of letters in the plaintext
		// and replace them with their corresponding
		// letters in the key matrix
		search(k1, C[i], C[i + 1], pos);

		// if the letters are in the same row
		if (pos[0] == pos[2])
		{
			C[i] = k1[pos[0]][(pos[1] - 1) % 5];
			C[i + 1] = k1[pos[0]][(pos[3] - 1) % 5];
		}
		// if the letters are in the same column
		else if (pos[1] == pos[3])
		{
			C[i] = k1[(pos[0] - 1) % 5][pos[1]];
			C[i + 1] = k1[(pos[2] - 1) % 5][pos[1]];
		}
		// none
		else
		{
			C[i] = k1[pos[0]][pos[3]];
			C[i + 1] = k1[pos[2]][pos[1]];
		}
	}
}

// decryption
void decrypt()
{

	// c3 affine decrpyt -> c2 caesar decrypt -> c1 playfair decrypt -> del

	char c[100];

	// 	take ciphertext as input
	printf("Enter ciphertext: ");
	gets(c);

	// decrypt c3 using affine cipher with key k3=(7, 5) -> c2
	int k3 = 17, k4 = 20;
	decrypt_a(c, k3, k4);

	// pritn c2
	printf("\n plain text, c2: %s\n", c);

	// decrypt c2 using caesar cipher with key k2=3 -> c1
	int k2 = 3;
	decrypt_c(c, k2);

	// print c1
	printf("\n plain text, c1: %s\n", c);

	// decrypt c1 using playfair cipher with key k1 -> del
	char key[100], k1[5][5];
	// print k1

	// take key as input
	printf("Enter key: ");
	gets(key);

	// convert J to I
	for (int i = 0; key[i] != '\0'; i++)
	{
		if (key[i] == 'j')
		{
			key[i] = 'i';
		}
	}

	// create 5*5 playfair matrix which is key k1
	int k_len = strlen(key);

	// taking a hash for storing count of each letter
	int *hash = (int *)calloc(26, sizeof(int));
	for (int i = 0; key[i] != '\0'; i++)
	{
		// make value of each letter as 2 so that we can create the matrix with only unique letters using 0 and 1
		hash[key[i] - 'a'] = 2;
	}

	// fill the matrix with letters in the key
	int x = 0, y = 0;
	for (int i = 0; i < k_len; i++)
	{
		if (hash[key[i] - 'a'] == 2)
		{
			k1[x][y] = key[i];
			hash[key[i] - 'a'] = 1;
			// increment column
			y++;
			if (y == 5)
			{
				// if column is full, increment row and reset column
				x++;
				y = 0;
			}
		}
	}

	// fill the matrix with remaining letters
	for (int i = 0; i < 26; i++)
	{
		if (hash[i] == 0 && (char)(i + 'a') != 'j')
		{
			k1[x][y] = 'a' + i; // error getting ascii
			hash[i] = 1;
			// increment column
			y++;
			if (y == 5)
			{
				// if column is full, increment row and reset column
				x++;
				y = 0;
			}
		}
	}

	int c_len = strlen(c);

	// decrypt del using playfair cipher with key k1 -> c1
	decrypt_pf(c, c_len, k1);

	// print c1
	printf("\n plain text, del: %s\n", c);
}
