#include "crylib.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>


// General
typedef unsigned char byte_t;


// for sha-256 hashing algorithm
#define MESSAGE_SCHEDULE_SIZE 256UL // size of the message schedule in bytes (512 bit)




// Helper Functions
void print_binary(byte_t byte)
{
    for (byte_t i = 128; i > 0; i/=2)
    {
        if (byte - i >= 0)
        {
            putchar('1');
            byte -= i;
        }
        else
        {
            putchar('0');
        }
    }
}


int is_little_endian() // test endianness of system
{
    uint32_t num = 1;
    if (*((byte_t*)&num) == 1)
        return 1;
    else
        return 0;
}

void reverse_bytes(uint32_t* p)
{
    for (size_t i = 0; i < 2; i++)
    {
        byte_t temp = ((byte_t*)p)[i];
        ((byte_t*)p)[i] = ((byte_t*)p)[3 - i];
        ((byte_t*)p)[3 - i] = temp;
    }
}

uint32_t rightrotate(uint32_t num, uint32_t rotation)
{
    uint32_t result = num >> rotation | num << (32 - rotation);

    return result;
}

// Helper Functions

// sha-256 algorithm for getting hash from password

int sha_256(const char input[])
{
    // STEP 1: Prepare Message Block

    const size_t input_length = strlen(input);
    size_t message_block_size = 64; // starting with 64 bytes = 512 bits

    while ((long)(message_block_size - input_length - 8 - 1) < 0) // if block wouldn't be big enough to fit password + extrabyte + 8-byte integer, increase blocksize by 512 bit
    {
        message_block_size += 64;
    }
    // prepare message block

    byte_t* message_block = malloc(message_block_size);

    size_t i = 0;
    // fill message block with password
    for (; i < input_length; i++)
    {
        message_block[i] = (byte_t)input[i];
    }

    // append the bits <10000000> 
    message_block[i] = (byte_t)128;

    // if on little-endian system, reverse each 4-byte sequence.
    if (is_little_endian())
    {
        const size_t last_row = (i / 4);
        for (size_t j = 0; j <= last_row; j++)
        {
            reverse_bytes(((uint32_t*)message_block) + j);
        }
    }

    // fill the remaining bytes with 0 except for the last 8
    for (i++; i < message_block_size - 8; i++)
    {
        message_block[i] = (byte_t)0;
    }

    // append the bit-length of input as 8-bytes integer
    size_t message_block_bit_length = input_length * sizeof(size_t); // length in bytes to bit-length
    const byte_t* size_as_byte_array = (void*)(&message_block_bit_length); // read 8-byte integer as 8 seperate bytes 

    if (is_little_endian())
    {
        *(uint32_t*)(message_block + i) = *(uint32_t*)(size_as_byte_array + 4);
        *(uint32_t*)(message_block + i + 4) = *(uint32_t*)(size_as_byte_array);
    }
    else
    {
        *(uint64_t*)(message_block + i) = *size_as_byte_array;
    }

    
    // print message block - just for debugging purposes
    puts("Message Block:");
    for (i = 0; i < message_block_size; i++)
    {
        print_binary(message_block[i]);
        putchar('\t');

        if ((i+1) % 4 == 0)
            putchar('\n');
    }



    // STEP 2: break down into 64-byte chunks
    const size_t num_chunks = message_block_size / 64;

    // repeat for each chunk:

    // STEP 3: Prepare Message Schedule

    // copy first chunk into message schedule
    uint32_t message_schedule[MESSAGE_SCHEDULE_SIZE] = {0};
    for (i = 0; i < 16; i++)
    {
        message_schedule[i] = ((uint32_t*)message_block)[i];
    }

    // print message schedule - just for debugging purposes
    puts("Message Schedule:");
    for (i = 0; i < MESSAGE_SCHEDULE_SIZE; i++)
    {
        print_binary(((byte_t *)message_schedule)[i]);
        putchar('\t');

        if ((i+1) % 4 == 0)
            putchar('\n');
    }


    // STEP 4: Calculate through Message Schedule
    for (i = 0; i <= 47; i++)
    {
        uint32_t w0 = message_schedule[i];
        uint32_t w1 = message_schedule[i + 1];
        uint32_t w9 = message_schedule[i + 9];
        uint32_t w14 = message_schedule[i + 14];

        uint32_t s0 = rightrotate(w1, 7) ^ rightrotate(w1, 18) ^ (w1 >> 3);
        uint32_t s1 = rightrotate(w14, 17) ^ rightrotate(w14, 19) ^ (w14 >> 10);
        message_schedule[i + 16] = w0 + s0 + w9 + s1;
    }

    // print message schedule - just for debugging purposes
    puts("Message Schedule:");
    for (i = 0; i < MESSAGE_SCHEDULE_SIZE; i++)
    {
        print_binary(((byte_t *)message_schedule)[i]);
        putchar('\t');

        if ((i+1) % 4 == 0)
            putchar('\n');
    }








    // free allocated memory
    free(message_block);


    return 0;





}













