#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char *buffer;
    long size;
} FileData;

typedef struct {
    FILE *file;
} FileReader;

int FileReader_open(FileReader *reader, const char *filename) {
    reader->file = fopen(filename, "rb");
    if (reader->file == NULL) {
        return 0;  // Return 0 if failed to open the file
    }
    return 1;  // Return 1 for success
}

void FileReader_close(FileReader *reader) {
    fclose(reader->file);
}

FileData FileReader_readIntoBuffer(FileReader *reader) {
    FileData data;

    fseek(reader->file, 0, SEEK_END);
    data.size = ftell(reader->file);
    rewind(reader->file);

    data.buffer = (char *)malloc(data.size + 1);

    if (data.buffer == NULL) {
        data.size = 0;  // Set size to 0 to indicate memory allocation failure
        return data;
    }

    fread(data.buffer, data.size, 1, reader->file);

    return data;
}

void FileData_free(FileData *data) {
    free(data->buffer);
}