#include "crylib.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>


// General
typedef unsigned char byte_t;

// for sha-256 hashing algorithm
#define MESSAGE_SCHEDULE_SIZE 256UL // size of the message schedule in bytes (512 bit)




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

uint32_t toggle_endian(uint32_t num) // converts small-endian integer to corresponding big-endian and vice versa 
{
    size_t size = sizeof(uint32_t);
    byte_t new_num_arr[size];
    for (size_t i = 0; i < size; i++)
    {
        new_num_arr[i] = ((byte_t*)&num)[size-i-1];
    }
    uint32_t new_num = *(uint32_t*)new_num_arr;
    return new_num;
}


uint32_t rightshift(uint32_t num, uint32_t shift)
{
    uint32_t result;
    if (is_little_endian())
        result = toggle_endian(toggle_endian(num) >> shift);
    else
        result = num >> shift;

    return result;
}

uint32_t leftshift(uint32_t num, uint32_t shift)
{
    uint32_t result;
    if (is_little_endian())
        result = toggle_endian(toggle_endian(num) << shift);
    else
        result = num << shift;

    return result;
}


uint32_t rightrotate(uint32_t num, uint32_t rotation)
{
    uint32_t result = rightshift(num, rotation) | leftshift(num, 32 - rotation);

    return result;
}

// sha-256 algorithm for getting hash from password

int sha_256(const char input[])
{
    // STEP 1: Prepare Message Block

    const size_t input_length = strlen(input);
    size_t message_block_size = 64; // starting with 64 bytes = 512 bits

    while ((long)(message_block_size - input_length - 8 - 1) < 0) // if block wouldn't be big enough to fit password + extrabyte + 8byte integer, increase blocksize by 512 bit
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
    i++;

    // fill the remaining bytes with 0 except for the last 8
    for (; i < message_block_size - sizeof(size_t); i++)
    {
        message_block[i] = (byte_t)0;
    }

    // append the bit-length of input as 8-bytes integer
    size_t message_block_bit_length = input_length * sizeof(size_t); // length in bytes to bit-length
    const byte_t* size_as_byte_array = (void*)(&message_block_bit_length); // read 8-byte integer as 8 seperate bytes 

    for (size_t j = 0; j < sizeof(size_t); j++) // copy over signle bytes of length integer
    {
        if (is_little_endian()) // for little endian systems
            message_block[i+j] = size_as_byte_array[sizeof(size_t) - 1 - j];
        else // for big endian systems
            message_block[i+j] = size_as_byte_array[j];
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

        uint32_t s0 = rightrotate(w1, 7) ^ rightrotate(w1, 18) ^ rightshift(w1, 3);
        uint32_t s1 = rightrotate(w14, 17) ^ rightrotate(w14, 19) ^ rightshift(w14, 10);
        if (is_little_endian())
            message_schedule[i + 16] = toggle_endian(toggle_endian(w0) + toggle_endian(s0) + toggle_endian(w9) + toggle_endian(s1));
        else
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













