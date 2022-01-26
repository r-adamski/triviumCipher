#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define STATE_SIZE 36
#define KEY_SIZE 10
#define IV_SIZE 10

void changeBit(uint8_t *array, uint16_t n, uint8_t value)
{
	uint8_t nbyte = (n - 1) / 8;
	uint8_t nbit = ((n - 1) % 8) + 1;

	array[nbyte] = ((255 << (9 - nbit)) & array[nbyte]) |
		(value << (8 - nbit)) |
		((255 >> nbit) & array[nbyte]);
}

uint8_t nbit(uint8_t *array, uint16_t n)
{
	uint8_t nbyte = (n - 1) / 8;
	uint8_t nbit = ((n - 1) % 8) + 1;
	return (array[nbyte] & (1 << (8 - nbit))) >> (8 - nbit);
}

// function performing one single rotation of the cipher state and returns z value
uint8_t rotate(uint8_t *arr, uint8_t arr_size)
{
	uint8_t i;

	uint8_t a1 = nbit(arr, 91) & nbit(arr, 92);
	uint8_t a2 = nbit(arr, 175) & nbit(arr, 176);
	uint8_t a3 = nbit(arr, 286) & nbit(arr, 287);

	uint8_t t1 = nbit(arr, 66) ^ nbit(arr, 93);
	uint8_t t2 = nbit(arr, 162) ^ nbit(arr, 177);
	uint8_t t3 = nbit(arr, 243) ^ nbit(arr, 288);

	uint8_t out = t1 ^ t2 ^ t3;

	uint8_t s1 = a1 ^ nbit(arr, 171) ^ t1;
	uint8_t s2 = a2 ^ nbit(arr, 264) ^ t2;
	uint8_t s3 = a3 ^ nbit(arr, 69) ^ t3;

	/* Begin rotate */

	for (i = arr_size - 1; i > 0; i--)
	{
		arr[i] = (arr[i - 1] << 7) | (arr[i] >> 1);
	}
	arr[0] = arr[0] >> 1;

	/* End rotate */

	changeBit(arr, 1, s3);
	changeBit(arr, 94, s1);
	changeBit(arr, 178, s2);

	return out;
}

void insertBits(uint8_t *arr, uint16_t n, uint8_t *source, uint16_t ssize)
{
	uint16_t i;
	for (i = 0; i < ssize; ++i)
	{
		changeBit(arr, n + i, nbit(source, i + 1));
	}
}

void initState(uint8_t *arr)
{
	uint16_t i;
	for (i = 0; i < 4 * 288; ++i)
	{
		rotate(arr, STATE_SIZE);
	}
}

uint8_t getByteFromGamma(uint8_t *arr)
{
	uint8_t buf = 0;
	uint8_t i = 0;
	while (i != 8)
	{
		uint8_t z = rotate(arr, STATE_SIZE);
		buf = buf | (z << i);
		i += 1;
	}
	return buf;
}

uint8_t hexDigitToInt(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;

	return -1;
}

uint8_t getByteFromConsole()
{
	uint8_t rb;
	uint8_t hc1, hc2;
	scanf("%c%c", &hc1, &hc2);
	rb = (hexDigitToInt(hc1) << 4) | (hexDigitToInt(hc2));
	return rb;
}

void getBytesFromConsole(int count, uint8_t* array)
{
	int i = 0;
	for (; i < 10; ++i)
	{
		array[i] = getByteFromConsole();
	}
}

int main(int argc, char **argv)
{
	uint8_t key[KEY_SIZE]; //80 bits
	uint8_t iv[IV_SIZE];  //80 bits
	uint8_t b[STATE_SIZE];	//288 bits
	uint8_t buffer;
	uint8_t encBuffer;
	uint8_t i;
	FILE * pFile;
	FILE * outFile;

	printf("Trivium cryptosystem.\n\nRA JH KRYS 2022\n\n");

	// init variables with 0
	for (i = 0; i < STATE_SIZE; ++i) b[i] = 0;
	for (i = 0; i < IV_SIZE; ++i) iv[i] = 0;
	for (i = 0; i < KEY_SIZE; ++i) key[i] = 0;

	// check if enough parameters provided
	if (argc != 3)
	{
		printf("Bad call parameters\n");
		printf("Usage: rajgTrivium.exe input.file output.file\n");
		return 0;
	}

	// open provided files
	printf("Input: '%s'\nOutput: '%s'\n", argv[1], argv[2]);
	pFile = fopen(argv[1], "rb");
	outFile = fopen(argv[2], "wb");
	if (pFile == NULL) { fputs("Input file error", stderr); exit(1); }
	if (outFile == NULL) { fputs("Output file error", stderr); exit(1); }

	// read key from console
	printf("Type key in hexadecimal format (80 bit/20 hex digits):\n");
	getBytesFromConsole(10, key);

	// read iv from console
	printf("Type initiation vector in hexadecimal format (80 bit/20 hex digits):\n");
	getBytesFromConsole(10, iv);

	// initialize cipher state with value
	insertBits(b, 1, key, 80);
	insertBits(b, 94, iv, 80);
	changeBit(b, 286, 1);
	changeBit(b, 287, 1);
	changeBit(b, 288, 1);

	// perform first 4*288 rotations
	initState(b);

	// start encryption / decryption
	while (fread(&buffer, 1, 1, pFile) != 0)
	{
		encBuffer = buffer ^ getByteFromGamma(b);
		fwrite(&encBuffer, 1, 1, outFile);
	}

	// closing input and output files
	fclose(pFile);
	fclose(outFile);
	return 0;
}

